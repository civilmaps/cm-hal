#include <iostream>
#include <string>
#include <vector>
#include <assert.h>
#include "../src/hal/laser_io.h"

using namespace std;
using namespace cm;

void test_read_vlp16_pcap(string pcap_input_abs_path, string relative_points_output_abs_path){
    vector<point_t> laser_records;
    laser_decoder my_laser_decoder(VELO_16_TYPE);
    my_laser_decoder.set_range(0,15); //we can change the distance range to filter as desired
    my_laser_decoder.read_velo_file(pcap_input_abs_path, laser_records);

    write_relative_points(relative_points_output_abs_path, laser_records);
}

int main(int argc, char **argv) {
    // Get the path and the name
    string pcap_input_abs_path = argv[1];
    string relative_points_output_abs_path = argv[2];
  
    test_read_vlp16_pcap(pcap_input_abs_path, relative_points_output_abs_path);
}
