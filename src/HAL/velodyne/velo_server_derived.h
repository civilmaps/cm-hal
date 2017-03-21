#ifndef __VELO_SERVER_DERIVED_H
#define __VELO_SERVER_DERIVED_H

#include "devkit/src/hal/laser_server.h"
#include "Poco/ClassLibrary.h"

#include <iostream>
#include <cstring>
#include <streambuf>
#include <sstream>

#include "Poco/Net/DatagramSocket.h"
#include "Poco/Net/SocketAddress.h"

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
#include <cm/common/cm_net/udp_client.h>

using namespace std;

namespace cm {
    /** derived class particular for the vlp 16 */
    class Velo_Server_Derived: public Laser_Server {
        private:
            Broadcast_Queue<point_t> *reg_records;//used in registration
            uint16_t udp_port;
            ofstream out_velo;
            string interface;
            bool log_data;
            incremental_laser_writer *my_laser_file_writer;
            Json::Value boresight_config;
            lidar_type_t lidar_type;
            double near_clip;
            double far_clip;
            bool overwrite_time;//used because xsens can't sync data so we have to use system clock
            bool is_des;
            chrono::high_resolution_clock::time_point t0, t1, t2, t3;
            Udp_Client *udp_log;
            double last_pcap_time, pcap_time_difference, approx_pkt_rate;

        public:
            Velo_Server_Derived() : Laser_Server () {} ;
            ~Velo_Server_Derived();
            string name() const { return "Velo_Server_Derived"; };
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
    POCO_EXPORT_CLASS(cm::Velo_Server_Derived)
POCO_END_MANIFEST

#endif
