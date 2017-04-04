#include <iostream>
#include "laser_io.h"

using namespace std;

namespace cm {

//constructor
laser_file_reader::laser_file_reader(unsigned int my_num_lasers) {
    num_lasers = my_num_lasers;
    this->my_pcap_file = 0;
}
//destructor
laser_file_reader::~laser_file_reader() {
    this->my_close();
}
//closing function used in a couple places
void laser_file_reader::my_close(){
    if(this->my_pcap_file) {
        pcap_close(this->my_pcap_file);
        this->my_pcap_file = 0;
        this->file_name.clear();
    }
}

//opening fun
bool laser_file_reader::my_open(const string& filename) {
    char err_buff[PCAP_ERRBUF_SIZE];
    pcap_t *tmp_pcap_file = pcap_open_offline(filename.c_str (), err_buff);
    if (!tmp_pcap_file) {
        cout << "pcap open fail: !tmp_pcap_file " << filename << endl;
        this->last_error = err_buff;
        return false;
    }

    struct bpf_program filter;

    //Check the LiDAR type to set the proper filter string
    const char *filter_string = num_lasers == QUANERGY_M8_TYPE ? "tcp" : "udp" ;
    if (pcap_compile(tmp_pcap_file, &filter, filter_string, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        cout << "pcap open fail: pcap_compile " << endl;

        this->last_error = pcap_geterr(tmp_pcap_file);
        return false;
    }

    if (pcap_setfilter(tmp_pcap_file, &filter) == -1) {
        this->last_error = pcap_geterr(tmp_pcap_file);
        cout << "pcap open fail: pcap_setfilter " << endl;
        return false;
    }
    this->file_name = filename;
    this->my_pcap_file = tmp_pcap_file;
    this->start_time.tv_sec = this->start_time.tv_usec = 0;
    return true;
}

// Same as my_open, but treats a string as a file for the benefit of
// libpcap (which only handles files).
// Remember that the pointer returned by blob.c_str() is valid only while
// blob stays unmodified.
bool laser_file_reader::my_open_str(const string& blob) {
    char err_buff[PCAP_ERRBUF_SIZE];
    FILE* pcap_buffer = fmemopen((void *)blob.c_str(), blob.size(), "r");
    pcap_t *tmp_pcap_file = pcap_fopen_offline(pcap_buffer, err_buff);
    if (!tmp_pcap_file) {
        this->last_error = err_buff;
        return false;
    }

    struct bpf_program filter;

    if (pcap_compile(tmp_pcap_file, &filter, "udp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        this->last_error = pcap_geterr(tmp_pcap_file);
        return false;
    }

    if (pcap_setfilter(tmp_pcap_file, &filter) == -1) {
        this->last_error = pcap_geterr(tmp_pcap_file);
        return false;
    }

    this->file_name = "<mem>";
    this->my_pcap_file = tmp_pcap_file;
    this->start_time.tv_sec = this->start_time.tv_usec = 0;
    return true;
}

bool laser_file_reader::is_open() {
    return (this->my_pcap_file != 0);
}

const string& laser_file_reader::get_file_name() {
    return this->file_name;
}

const string& laser_file_reader::get_last_error() {
    return this->last_error;
}

void laser_file_reader::get_file_position(fpos_t* position) {
    #ifdef _MSC_VER
        pcap_fgetpos(this->my_pcap_file, position);
    #else
        FILE* f = pcap_file(this->my_pcap_file);
        fgetpos(f, position);
    #endif
}

void laser_file_reader::set_file_position(fpos_t* position) {
    #ifdef _MSC_VER
        pcap_fsetpos(this->my_pcap_file, position);
    #else
        FILE* f = pcap_file(this->my_pcap_file);
        fsetpos(f, position);
    #endif
}

//logic to get the next packet
bool laser_file_reader::next_packet(const unsigned char*& data, unsigned int& data_length, double& time_since_start, pcap_pkthdr** header_reference=NULL) {
    if (!this->my_pcap_file) {
        return false;
    }
    //cout << header-> pcap-tstamp <<endl;
    struct pcap_pkthdr *header;
    int return_value = pcap_next_ex(this->my_pcap_file, &header, &data);
    if (return_value < 0) {
        this->my_close();
        return false;
    }

    if (header_reference != NULL) {
        *header_reference = header;
        data_length = header->len;
        time_since_start = get_elapsed_time(header->ts, this->start_time);
        return true;
    }

    switch(num_lasers) {
        case QUANERGY_M8_TYPE:
            data_length = header->len - BYTES_TO_SKIP_TO_M8_HEADER;
            data = data + BYTES_TO_SKIP_TO_M8_HEADER;
            time_since_start = (header->ts.tv_sec) + ((header->ts.tv_usec) / 1000000.00);
            //cout<<"m8 type"<<endl;
            break;
        case VELO_16_TYPE:
        case VELO_32_TYPE:
        case VELO_64_TYPE:
            data_length = header->len - VELO_BYTES_TO_SKIP;
            data = data + VELO_BYTES_TO_SKIP;
            time_since_start = get_elapsed_time(header->ts, this->start_time);
            //cout << "time since start: " << time_since_start << endl;
            break;
    }
    //cout<<time_since_start<<endl;
    return true;
}

double laser_file_reader::get_elapsed_time(const struct timeval& end, const struct timeval& start) {
    return (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.00;
}

////////////////////
/////Laser Decoder//
////////////////////
laser_decoder::laser_decoder(unsigned int my_num_lasers){
    override_pcap_time = false; //Set the top of hour time override to false by default
    top_of_hour_override = 0;
    //check if vlp16 or hdl32/64 or m8, abort otherwise
    if(my_num_lasers != QUANERGY_M8_TYPE && my_num_lasers != VELO_16_TYPE && my_num_lasers != VELO_32_TYPE && my_num_lasers != VELO_64_TYPE) { 
        cout <<"incorrect number of lasers in constructor: "<<my_num_lasers<<endl;
        exit(1);
    }

    if(my_num_lasers == VELO_64_TYPE) {
        HDL64_config_loaded = false;
    }

    num_lasers = my_num_lasers;
    reader = new laser_file_reader(num_lasers);
    //Populate the horizontal angle lookup table if we're using an M8
    if (num_lasers == QUANERGY_M8_TYPE) {
        for (uint32_t i = 0; i <= M8_NUM_ROT_ANGLES; i++) {
            // Shift by half the rot angles to keep the number positive when wrapping.
            uint32_t j = (i + M8_NUM_ROT_ANGLES/2) % M8_NUM_ROT_ANGLES;
            // normalized
            double n = static_cast<double>(j) / static_cast<double>(M8_NUM_ROT_ANGLES);
            double rad = n * M_PI * 2.0 - M_PI;
            M8_HORIZONTAL_ANGLE_LOOKUP_TABLE[i] = rad;
        }
    }

    output_log_mode = false;
    num_packets_to_read = -1; //-1 reads all packets. Set to read all by default
}

void laser_decoder::read_velo_file(string filename, vector<point_t> &laser_records){
    
    if (!this->reader->my_open(filename)) {
        cout << "Failed to open packet file: " << filename << endl << this->reader->get_last_error();
        return;
    } else
        cout << "Opened pcap file" <<endl;
    
    const unsigned char* data = 0;
    unsigned int data_length = 0;
    double time_since_start = 0;
    int record_num = 0;

    fpos_t last_file_position;
    this->reader->get_file_position(&last_file_position);
    
    while (this->reader->next_packet(data, data_length, time_since_start)) {

        //Verify our data length matches the proper LiDAR type
        switch(num_lasers) {
            case QUANERGY_M8_TYPE:
                if (data_length != M8_PACKET_SIZE)
                    continue;
                else
                    break;
            case VELO_16_TYPE:
            case VELO_32_TYPE:
            case VELO_64_TYPE:
                if (data_length != VELO_DATA_LENGTH)
                    continue;
                else
                    break;
        }

        record_num++;
        get_records_from_packet(reinterpret_cast<const char *>(data), time_since_start, laser_records);
        //Break if we reach the max number of packets to read and are in log mode and not reading all packets
        if (record_num >= num_packets_to_read && output_log_mode && num_packets_to_read != -1){
            break;
        }
        this->reader->get_file_position(&last_file_position);
    }

    if(output_log_mode)
        fclose(myfile);
}

// Exactly the same as above, but uses reader->my_open_strs()
void laser_decoder::read_velo_str(string &blob, vector<point_t> &laser_records){
    
    if (!this->reader->my_open_str(blob)) {
        cout << "Failed to open PCAP blob:\n" << this->reader->get_last_error();
        return;
    }
    
    const unsigned char* data = 0;
    unsigned int data_length = 0;
    double time_since_start = 0;

    fpos_t last_file_position;
    this->reader->get_file_position(&last_file_position);

    //const data_packet_t* data_packet;

    while (this->reader->next_packet(data, data_length, time_since_start)) {
        //cout <<data_length<< " " <<time_since_start<<endl;
        switch(num_lasers) {
            case QUANERGY_M8_TYPE:
                if (data_length != M8_PACKET_SIZE)
                    continue;
                else
                    break;
            case VELO_16_TYPE:
            case VELO_32_TYPE:
            case VELO_64_TYPE:
                if (data_length != VELO_DATA_LENGTH)
                    continue;
                else
                    break;
        }
        //printf("%f \n", time_since_start);
        //data_packet = reinterpret_cast<const data_packet_t *>(data);//i don't know about reinterpret_cast here

        get_records_from_packet(reinterpret_cast<const char *>(data), time_since_start, laser_records);
    }
}

void laser_decoder::get_records_from_packet(const char *data_packet_bytes, double packet_timestamp, vector<point_t> &laser_records) {

    const firing_data_t *firing_data, *next_firing_data;
    const laser_return_t *laser_return;
    point_t laser_record;
    float start_azimuth, end_azimuth, previous_azimuth_offset, az_rad, radius, azimuth;
    vector<double> azimuths(LASER_PER_FIRING);//to hold the azimuth angle for each laser 
    check_top_of_hour_override_time(packet_timestamp);
    
    if (num_lasers == VELO_16_TYPE) {
        //transform velo caps into laser records
        const data_packet_t* data_packet = reinterpret_cast<const data_packet_t *>(data_packet_bytes);
        double packet_utc_timestamp = compute_timestamp(packet_timestamp, data_packet->gps_timestamp);
        for (unsigned int i = 0; i < FIRING_PER_PKT; ++i) {
            firing_data = &(data_packet->firing_data[i]);
            /*Interpolate azimuths:
            We use the offset between the current azimuth and next azimuth angle to interpolate the azimuth angles inbetween. If we are at the last firing sequence, we use the previous azimuth offset
            */
            
            start_azimuth = static_cast<float>(firing_data->rotational_position) / 100.0;
            // cout << "start azimuth: " << start_azimuth << endl;
            if (i < FIRING_PER_PKT - 1){ //not the last firing sequence
                next_firing_data = &(data_packet->firing_data[i+1]);
                end_azimuth = (next_firing_data->rotational_position) / 100.0;
                if (end_azimuth < start_azimuth){
                    end_azimuth += 360.0; //handle rollover
                }
            } else {
                end_azimuth = start_azimuth + previous_azimuth_offset;
            }
            previous_azimuth_offset = end_azimuth - start_azimuth; //used for the last firing sequence
            
            for (int dsr = 0; dsr < LASER_PER_FIRING; dsr++) {
                // cout << "laser per firing: " << dsr << endl;
                laser_return = &(firing_data->laser_returns[dsr]);
                radius = static_cast<float>(laser_return->distance) / 1000.0 * 2;//2mm increments
                laser_record.intensity = static_cast<float>(laser_return->intensity);
                
                //is this firing within the desired range (min max)?
                if (radius < this->range_min || radius > this->range_max){
                    continue;
                }
                
                int dsr_temp=dsr;
                int firingblock=0;
                if (dsr>15) {
                    dsr_temp = dsr-16;
                    firingblock=1;
                } 

                double timestamp_adjustment = (i * 110.592) + (dsr_temp * 2.304) + (firingblock * 55.296);

                azimuth = start_azimuth;

                //get the corrected time
                laser_record.time = packet_utc_timestamp + timestamp_adjustment / 1e6;//from us to s

                //get the cartesian coordinates for the record
                az_rad = to_radians(azimuth);
                laser_record.x_relative = radius * ELEVATION_ANGLES_COS_RAD_16[dsr] * sin(az_rad);//negative because of the right hand plane
                laser_record.y_relative = radius * ELEVATION_ANGLES_COS_RAD_16[dsr] * cos(az_rad);
                laser_record.z_relative = radius * ELEVATION_ANGLES_SIN_RAD_16[dsr];

                if(output_log_mode) {
                            fprintf(myfile, "%10.2f %10.2f %10.2f %10.1f %10.17f\n",
                             laser_record.x_relative,
                             laser_record.y_relative,
                             laser_record.z_relative,
                             laser_record.intensity,
                             laser_record.time);
                } else {
                    // append record to vector
                    laser_records.push_back(laser_record);
                }

                laser_records.push_back(laser_record);  
            }
        }
    }
}

void laser_decoder::set_range(float range_min, float range_max){
    this->range_min = range_min;
    this->range_max = range_max;
};

void laser_decoder::set_log_mode(bool mode) {
    output_log_mode = mode;
}

void laser_decoder::set_output_log_file(string file_path) {
    output_log_file = file_path;
    myfile = fopen (file_path.c_str(),"w");
}

//0 by default
//-1 to read all packets
//positive integer n to read n number of packets
void laser_decoder::set_num_packets_to_read(int num_packets) {
    num_packets_to_read = num_packets;
}

//Overrides the timestamp passed by reference if the override and new time are set
void laser_decoder::check_top_of_hour_override_time(double &packet_timestamp) {
    if (override_pcap_time && top_of_hour_override > 0) {
        packet_timestamp = top_of_hour_override;
    }
}

double laser_decoder::compute_timestamp(double packet_timestamp, unsigned int top_hour_timestamp) {
    double top_of_hour;
    
    if (does_udp_hour_match_velodyne(packet_timestamp, top_hour_timestamp)) {
        top_of_hour = packet_timestamp - fmod(packet_timestamp, 3600);
    } else {
        top_of_hour = get_correct_top_of_hour(packet_timestamp, top_hour_timestamp);
    }

    double seconds_from_top_of_hour = top_hour_timestamp/1000000.0;

    return top_of_hour + seconds_from_top_of_hour;
}

//MAX_TIME_DIFF_BEFORE_WARNING = 1000000 * 5 # microseconds
bool laser_decoder::does_udp_hour_match_velodyne(double packet_timestamp, unsigned int velodyne_timestamp) {
    /*Confirms the udp timestamps hour makes sense with the input velodyne timestamp.

    The velodyne timestamp is given as microseconds from the top of the hour
    There is some drift between the packet_timestamp and the gps time the velodyne uses.
    If the velodyne time is 12:01 and the udp timestamp is 11:59, the velodyne_timestamp
    will equal 1 minute and and udp timestamp will be 59 minutes past the hour.

    Assuming the max difference between the clocks is less than a few seconds,
    if there is a difference greater than that, we know it is because of the hour
    rollover
    */
    double top_of_hour = packet_timestamp - fmod(packet_timestamp, 3600);
    double microseconds_from_top_of_hour = (packet_timestamp - top_of_hour)*1000000;
    double time_difference = abs(microseconds_from_top_of_hour - velodyne_timestamp);

    if (time_difference > MAX_TIME_DIFFERENCE) {
        return false;
    } else {
        return true;
    }
}

double laser_decoder::get_correct_top_of_hour(double packet_timestamp, unsigned int velodyne_timestamp) {
    /*Returns the correct hour
    The velodyne uses gps time which is more accurate than the packet_timestamp.
    If the velodyne time is 12:01 the velodyne_timestamp will equal 1 minute.
    If the packet_timestamp equals 11:59 we can assume the true hour is 12:00
    */
    
    double top_of_hour = packet_timestamp - fmod(packet_timestamp, 3600);
    double microseconds_from_top_of_hour = (packet_timestamp - top_of_hour)*1000000;
    double time_difference = microseconds_from_top_of_hour - velodyne_timestamp;

    if (time_difference > 0) {
    // Velodyne time says udp top of hour is behind (e.g. udp=12:59, velodyne=1:01)
        top_of_hour = packet_timestamp + (3600 - fmod(packet_timestamp, 3600));
    } else if (time_difference < 0) {
    // Velodyne time says udp top of hour is ahead (e.g. udp=12:01, velodyne=11:59)
        top_of_hour = packet_timestamp - fmod(packet_timestamp, 3600) - 3600;
    } else {
        //log.warning('This shouldnt happen. Current pcap reader should not call this if the udp hour and velodyne hour match')
        top_of_hour = packet_timestamp - fmod(packet_timestamp, 3600);
    }
    return top_of_hour;
}

void laser_decoder::set_top_of_hour(double top_hour_timestamp){
    top_of_hour_override = top_hour_timestamp;
}

void laser_decoder::set_override_pcap_time(bool toggle){
    override_pcap_time = toggle;
}

}
