#include "velo_server_derived.h"

using namespace std;

namespace cm {

    void Velo_Server_Derived::init(Json::Value my_config, Broadcast_Queue<point_t> *my_reg_records, bool my_log_data = false, string my_dir=""){
        udp_port = my_config["settings"]["data_port"].asUInt();//assign udp port to filter incoming packets
        cout <<"udp port: "<<udp_port<<endl;
        interface = my_config["settings"]["iface"].asString();
        if (my_config["settings"]["lidar_type"] == "QUANERGY_M8_TYPE") {
            lidar_type = QUANERGY_M8_TYPE;
        } else if (my_config["settings"]["lidar_type"] == "VELO_16_TYPE") {
            lidar_type = VELO_16_TYPE;
        } else if (my_config["settings"]["lidar_type"] == "VELO_32_TYPE") {
            lidar_type = VELO_32_TYPE;
        } else if (my_config["settings"]["lidar_type"] == "VELO_64_TYPE") {
            lidar_type = VELO_64_TYPE;
        } else {
            cout <<"unknown lidar_type in lidar sensor config[\"settings\"][\"lidar_type\"]"<<endl;
            exit(-1);
        }
        near_clip = my_config["settings"]["near_clip"].asDouble();
        far_clip = my_config["settings"]["far_clip"].asDouble();
        overwrite_time = my_config["settings"]["overwrite_time"].asBool();
        is_des = my_config["settings"]["is_des"].asBool();
        reg_records = my_reg_records;
        log_data = my_log_data;
        if(log_data) {
            const unsigned int num_packets_per_file = 100000;
            my_laser_file_writer = new incremental_laser_writer(num_packets_per_file, my_dir+"pcaps/"+"velo_output", lidar_type);
        }
        
        udp_log = new Udp_Client(my_config["logging"]["ip"].asString(), my_config["logging"]["port"].asUInt());
        //out_velo.open("velo_output.dat");
    };
    Velo_Server_Derived::~Velo_Server_Derived(){
    };
    
    void Velo_Server_Derived::runTask(){
        // Get boresighting info
        cv::Mat boresight_mat = get_boresight_mat_from_config(boresight_config);

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* descr;
        struct pcap_pkthdr *pkthdr;
        const uint8_t *packet;
        uint16_t curr_udp_port;
        velo_cap_t curr_cap;
        //char velo_dsk[sizeof(velo_cap_t)];
        unsigned char* data = 0;
        double time_since_start = 0;
        //const data_packet_t* data_packet;
        vector<point_t> temp_laser_records;
        unsigned int i;
        laser_decoder my_laser_decoder(lidar_type);
        my_laser_decoder.set_range(near_clip,far_clip);//meters
        unsigned int packet_count = 0;
        
        t0 = chrono::high_resolution_clock::now();
        t2 = chrono::high_resolution_clock::now();
        
        // open device
        descr = pcap_open_live(interface.c_str(),BUFSIZ,0,-1,errbuf);
        if(descr == NULL) { printf("pcap_open_live(): %s\n",errbuf); exit(1); }
        //wait for packets and call callback
        while(!this->isCancelled()){
            if(pcap_next_ex(descr, &pkthdr, &packet)) { //PACK
                
                if(is_des) {
                    curr_udp_port = packet[36]*256 + packet[37];
                } else {
                    curr_udp_port = packet[36]*256 + packet[35];
                }
                if(curr_udp_port == this->udp_port){
                    
                    //printf("port number %i\n", udp_port);
                    memcpy(&(curr_cap.header), pkthdr, sizeof(pcap_pkthdr));
                    if(is_des) { //get extra 8 bytes for the time stamp
                        memcpy(curr_cap.packet, packet, sizeof(curr_cap.packet)+sizeof(double));
                    } else {
                        memcpy(curr_cap.packet, packet, sizeof(curr_cap.packet));
                    }
                    
                    data = curr_cap.packet + VELO_BYTES_TO_SKIP;
                    
                    if(overwrite_time) {
                        //because of the xsens pulse not being in phase with the gps pulse, this hack allows us to estimate the top of the hour timestamp:
                        uint32_t temp_top_of_hour = ((curr_cap.header.ts.tv_sec) % 3600) * 1000000 + (curr_cap.header.ts.tv_usec - 1327);//where 1327 us is the time to fire all 24 blocks of 12 packets.
                        //cout <<"top of hour: "<<temp_top_of_hour<<" "<<uint16_t(data[1200+0])<<" "<<uint16_t(data[1200+1])<<" "<<uint16_t(data[1200+2])<<" "<<uint16_t(data[1200+3])<<endl;
                        data[1200+0] = uint8_t(temp_top_of_hour >> 0);
                        data[1200+1] = uint8_t(temp_top_of_hour >> 8);
                        data[1200+2] = uint8_t(temp_top_of_hour >> 16);
                        data[1200+3] = uint8_t(temp_top_of_hour >> 24);//*/
                        
                    }

                    if(is_des) { //get the extra 8 bytes which define the original timestamp at which the packet was sent
                        memcpy(&time_since_start, data+1206, sizeof(double));
                    } else {
                        time_since_start = (curr_cap.header.ts.tv_sec) + (curr_cap.header.ts.tv_usec) / 1000000.00; //assumes the machine clock is in utc and that the kernel has been compiled with the flag for capturing packet timestamps
                    }
                    
                    //calculate and log packet rx rate
                    if(++packet_count % 10000 == 0) {
                        t1 = chrono::high_resolution_clock::now();
                        approx_pkt_rate = 10000.0*1000.0/ double(chrono::duration_cast<chrono::milliseconds>( t1 - t0 ).count());
                        cout << "driver approximate pcap rate rx rate (pkts/sec) " << approx_pkt_rate << endl;
                        t0 = t1;
                        Json::Value payload;
                        payload["sensor"]["lidar"]["approx_pps"] = approx_pkt_rate;
                        udp_log->send_pkt(payload);
                        
                    }
                    
                    //every second
                    t3 = chrono::high_resolution_clock::now();
                    if (double(chrono::duration_cast<chrono::milliseconds>( t3 - t2 ).count()) > 1000) {
                        //calculate time difference
                        double now = chrono::duration_cast<chrono::milliseconds>(chrono::system_clock::now().time_since_epoch()).count();
                        now = now/1000.0;
                        pcap_time_difference = now - time_since_start;
                        t2 = t3;
                        
                        //log freshness
                        Json::Value payload;
                        payload["sensor"]["lidar"]["freshness"] = pcap_time_difference;
                        udp_log->send_pkt(payload);
                        
                    }
                    
                    //data_packet = reinterpret_cast<const data_packet_t *>(data);
                    my_laser_decoder.get_records_from_packet(reinterpret_cast<const char *>(data), time_since_start, temp_laser_records);

                    // Boresight the points before pushing to vector
                    boresight(temp_laser_records, boresight_mat);

                    //push it into the vector
                    for (i=0;i<temp_laser_records.size();i++) {
                        reg_records->try_enqueue(temp_laser_records[i]);
                    }
                    //clear the temporary vector: feels like this isn't great for memory allocation
                    //TODO we know how many records each packet contains, so we can make sure the vector is in a constant memory space
                    temp_laser_records.clear();

                    //copy velo cap to local disk
                    if(log_data) {
                        my_laser_file_writer->write_packet(pkthdr, const_cast<unsigned char *>(curr_cap.packet));
                    }

                }
            } else {//NO PACK
                usleep(1000);
            }
        }

    }
}
