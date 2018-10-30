//
// Twili - Homebrew debug monitor for the Nintendo Switch
// Copyright (C) 2018 misson20000 <xenotoad@xenotoad.net>
//
// This file is part of Twili.
//
// Twili is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Twili is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Twili.  If not, see <http://www.gnu.org/licenses/>.
//

#include "SocketFrontend.hpp"

#include "platform.hpp"

#include<algorithm>
#include<iostream>

#include<string.h>

#include "Twibd.hpp"
#include "Protocol.hpp"
#include "config.hpp"

namespace twili {
namespace twibd {
namespace frontend {

SocketFrontend::SocketFrontend(Twibd &twibd, int address_family, int socktype, struct sockaddr *bind_addr, size_t bind_addrlen) :
	twibd(twibd),
	address_family(address_family),
	socktype(socktype),
	bind_addrlen(bind_addrlen),
	notifier(*this) {

	if(bind_addr == NULL) {
		LogMessage(Fatal, "failed to allocate bind_addr");
		exit(1);
	}
	memcpy((char*) &this->bind_addr, bind_addr, bind_addrlen);
	
	fd = socket(address_family, socktype, 0);
	if(fd == INVALID_SOCKET) {
		LogMessage(Fatal, "failed to create socket: %s", NetErrStr());
		exit(1);
	}
	
	LogMessage(Debug, "created socket: %d", fd);

	if(address_family == AF_INET6) {
		int ipv6only = 0;
		if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*) &ipv6only, sizeof(ipv6only)) == -1) {
			LogMessage(Fatal, "failed to make ipv6 server dual stack: %s", NetErrStr());
		}
	}

	UnlinkIfUnix();
	
	if(bind(fd, bind_addr, bind_addrlen) < 0) {
		LogMessage(Fatal, "failed to bind socket: %s", NetErrStr());
		closesocket(fd);
		exit(1);
	}

	if(listen(fd, 20) < 0) {
		LogMessage(Fatal, "failed to listen on socket: %s", NetErrStr());
		closesocket(fd);
		UnlinkIfUnix();
		exit(1);
	}

#ifndef _WIN32
	if(pipe(event_thread_notification_pipe) < 0) {
		LogMessage(Fatal, "failed to create pipe for event thread notifications: %s", NetErrStr());
		closesocket(fd);
		UnlinkIfUnix();
		exit(1);
	}
#endif // _WIN32

	std::thread event_thread(&SocketFrontend::event_thread_func, this);
	this->event_thread = std::move(event_thread);
}

SocketFrontend::SocketFrontend(Twibd &twibd, int fd) :
	twibd(twibd),
	fd(fd),
	address_family(0),
	socktype(SOCK_STREAM),
	notifier(*this) {

#ifndef _WIN32
	if(pipe(event_thread_notification_pipe) < 0) {
		LogMessage(Fatal, "failed to create pipe for event thread notifications: %s", NetErrStr());
		closesocket(fd);
		UnlinkIfUnix();
		exit(1);
	}
#endif // _WIN32

	std::thread event_thread(&SocketFrontend::event_thread_func, this);
	this->event_thread = std::move(event_thread);
}

SocketFrontend::~SocketFrontend() {
	event_thread_destroy = true;
	NotifyEventThread();
	event_thread.join();
	
	closesocket(fd);
	UnlinkIfUnix();
#ifndef _WIN32
	close(event_thread_notification_pipe[0]);
	close(event_thread_notification_pipe[1]);
#endif
}

void SocketFrontend::UnlinkIfUnix() {
#ifndef WIN32
	if(address_family == AF_UNIX) {
		unlink(((struct sockaddr_un*) &bind_addr)->sun_path);
	}
#endif
}

void SocketFrontend::event_thread_func() {
	fd_set readfds;
	fd_set writefds;
	SOCKET max_fd = 0;
	while(!event_thread_destroy) {
		LogMessage(Debug, "socket event thread loop");
		
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		// add server socket
		max_fd = std::max(max_fd, fd);
		FD_SET(fd, &readfds);

#ifndef _WIN32
		// add event thread notification pipe
		max_fd = std::max(max_fd, event_thread_notification_pipe[0]);
		FD_SET(event_thread_notification_pipe[0], &readfds);
#endif
		
		// add client sockets
		for(auto &c : clients) {
			max_fd = std::max(max_fd, c->connection.fd);
			FD_SET(c->connection.fd, &readfds);
			
			if(c->connection.HasOutData()) { // only add to writefds if we need to write
				FD_SET(c->connection.fd, &writefds);
			}
		}

		if(select(max_fd + 1, &readfds, &writefds, NULL, NULL) < 0) {
			LogMessage(Fatal, "failed to select file descriptors: %s", NetErrStr());
			exit(1);
		}

#ifndef _WIN32
		// Check select status on event thread notification pipe
		if(FD_ISSET(event_thread_notification_pipe[0], &readfds)) {
			char buf[64];
			ssize_t r = read(event_thread_notification_pipe[0], buf, sizeof(buf));
			if(r < 0) {
				LogMessage(Fatal, "failed to read from event thread notification pipe: %s", strerror(errno));
				exit(1);
			}
			LogMessage(Debug, "event thread notified: '%.*s'", r, buf);
		}
#endif
		
		// Check select status on server socket
		if(FD_ISSET(fd, &readfds)) {
			LogMessage(Debug, "incoming connection detected on %d", fd);

			int client_fd = accept(fd, NULL, NULL);
			if(client_fd < 0) {
				LogMessage(Warning, "failed to accept incoming connection");
			} else {
				std::shared_ptr<Client> c = std::make_shared<Client>(client_fd, *this);
				clients.push_back(c);
				twibd.AddClient(c);
			}
		}
		
		// pump i/o
		for(auto mci = clients.begin(); mci != clients.end(); mci++) {
			std::shared_ptr<Client> &c = *mci;
			if(FD_ISSET(c->connection.fd, &writefds)) {
				if(!c->connection.PumpOutput()) {
					c->deletion_flag = true;
				}
			}
			if(FD_ISSET(c->connection.fd, &readfds)) {
				LogMessage(Debug, "incoming data for client %x", c->client_id);
				if(!c->connection.PumpInput()) {
					c->deletion_flag = true;
				}
			}
		}

		for(auto i = clients.begin(); i != clients.end(); ) {
			twibc::MessageConnection::Request *rq;
			while((rq = (*i)->connection.Process()) != nullptr) {
				LogMessage(Debug, "posting request");
				twibd.PostRequest(
					Request(
						*i,
						rq->mh.device_id,
						rq->mh.object_id,
						rq->mh.command_id,
						rq->mh.tag,
						std::vector<uint8_t>(rq->payload.Read(), rq->payload.Read() + rq->payload.ReadAvailable())));
				LogMessage(Debug, "posted request");
			}
			
			if((*i)->deletion_flag) {
				twibd.RemoveClient(*i);
				i = clients.erase(i);
				continue;
			}

			i++;
		}
	}
}

void SocketFrontend::NotifyEventThread() {
#ifdef _WIN32
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	if(getsockname(fd, (struct sockaddr*) &addr, &addrlen) != 0) {
		LogMessage(Fatal, "failed to get local server address: %s", NetErrStr());
		exit(1);
	}

	// Connect to the server in order to wake it up
	SOCKET cfd = socket(addr.ss_family, socktype, 0);
	if(cfd < 0) {
		LogMessage(Fatal, "failed to create socket: %s", NetErrStr());
		exit(1);
	}

	if(connect(cfd, (struct sockaddr*) &addr, addrlen) < 0) {
		LogMessage(Fatal, "failed to connect for notification: %s", NetErrStr());
		exit(1);
	}
	
	closesocket(cfd);
#else
	char buf[] = ".";
	if(write(event_thread_notification_pipe[1], buf, sizeof(buf)) != sizeof(buf)) {
		LogMessage(Fatal, "failed to write to event thread notification pipe: %s", strerror(errno));
		exit(1);
	}
#endif
}

SocketFrontend::Client::Client(SOCKET fd, SocketFrontend &frontend) : connection(fd, frontend.notifier), frontend(frontend), twibd(frontend.twibd) {
}

SocketFrontend::Client::~Client() {
	LogMessage(Debug, "destroying client 0x%x", client_id);
}

void SocketFrontend::Client::PostResponse(Response &r) {
	protocol::MessageHeader mh;
	mh.device_id = r.device_id;
	mh.object_id = r.object_id;
	mh.result_code = r.result_code;
	mh.tag = r.tag;
	mh.payload_size = r.payload.size();
	mh.object_count = r.objects.size();
	
	std::vector<uint32_t> object_ids(r.objects.size(), 0);
	std::transform(
		r.objects.begin(), r.objects.end(), object_ids.begin(),
		[](auto const &object) {
			return object->object_id;
		});

	connection.SendMessage(mh, r.payload, object_ids);
}

SocketFrontend::EventThreadNotifier::EventThreadNotifier(SocketFrontend &frontend) : frontend(frontend) {
}

void SocketFrontend::EventThreadNotifier::Notify() {
	frontend.NotifyEventThread();
}

} // namespace frontend
} // namespace twibd
} // namespace twili
