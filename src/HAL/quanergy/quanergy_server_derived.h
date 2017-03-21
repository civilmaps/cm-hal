#ifndef __QUANERGY_SERVER_DERIVED_H
#define __QUANERGY_SERVER_DERIVED_H

#include "devkit/src/hal/laser_server.h"
#include "Poco/ClassLibrary.h"

#include <iostream>
#include <cstring>
#include <streambuf>
#include <sstream>

#include "Poco/Net/DatagramSocket.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Net/SocketStream.h"
#include "Poco/Exception.h"

#include <cm/common/cm_types/cm_types.h>
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
#include <cm/common/cm_reg_cpp/laser/laser_io.h>

using namespace std;

namespace cm {

    class Quanergy_Server_Derived: public Laser_Server {
        private:
            Broadcast_Queue<point_t> *reg_records;//used in registration
            uint16_t tcp_port;
            ofstream out_quanergy;
            string interface;
            string m8_ip_address;
            Poco::Net::StreamSocket my_stream_socket;
            char receive_buffer[M8_PACKET_SIZE*6]; //Make the receive buffer large enough to hold 6 full packets
            lidar_type_t lidar_type;
            bool log_data;
            bool print_points_to_terminal;
            bool print_points_to_file;
            bool is_des;
            string my_point_log_file_name;
            incremental_laser_writer *my_laser_file_writer;
            Json::Value boresight_config;
            double near_clip;
            double far_clip;
            bool getBytes();
            void openSocket();

        public:
            Quanergy_Server_Derived() : Laser_Server () {} ;
            ~Quanergy_Server_Derived();
            string name() const { return "Quanergy_Server_Derived"; };
            void init(Json::Value my_config, Broadcast_Queue<point_t> *my_reg_records, bool my_log_data, string my_dir);
            
            Json::Value get_boresight_config() {
                return boresight_config;
            };
            
            void set_boresight_config(Json::Value config) {
                boresight_config = config;
            }; 
            
            void runTask();
    };
    
}

POCO_BEGIN_MANIFEST(cm::Laser_Server)
    POCO_EXPORT_CLASS(cm::Quanergy_Server_Derived)
POCO_END_MANIFEST

#endif
