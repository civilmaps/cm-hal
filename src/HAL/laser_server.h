#ifndef __LASER_SERVER_H
#define __LASER_SERVER_H

#include <iostream>
#include <cstring>
#include <streambuf>
#include <sstream>

#include "Poco/Mutex.h"

#include "Poco/Net/DatagramSocket.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Thread.h"
#include "Poco/Task.h"
#include <common/cm_types/cm_types.h>
#include <vector>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <json/json.h>

using namespace std;

namespace cm {
    /** Base class for laser sensor drivers */
    class Laser_Server: public Poco::Task {
        public:
            Laser_Server () : Task("Laser_Server_Task") {};
            virtual ~Laser_Server() {};
            virtual string name() const = 0;
            virtual void init(Json::Value my_config, Broadcast_Queue<point_t> *my_reg_records, bool my_log_data, string my_dir) = 0;
            virtual Json::Value get_boresight_config() = 0;
            virtual void set_boresight_config(Json::Value config) = 0;
            virtual void runTask() = 0;
    };
}

#endif
