#ifndef __POINT_H
#define __POINT_H
#include <vector>
#include <json/json.h>
#include <sstream>
#include <fstream>
#include <iostream>
#include <random>

using namespace std;

namespace cm {

    //////////////////////////
    // point_t ///////////////
    //////////////////////////
    /*

    Common point_t struct

    time: unix time when point was captured
    x : x position of point after registered to global frame
    y : y position of point after registered to global frame
    z : z position of point after registered to global frame
    x_relative : x position of point relative to laser (if transform_state=RAW) or to the imu (if transform_state=BORESIGHTED or REGISTERED)
    y_relative : y position of point relative to laser (if transform_state=RAW) or to the imu (if transform_state=BORESIGHTED or REGISTERED)
    z_relative : z position of point relative to laser (if transform_state=RAW) or to the imu (if transform_state=BORESIGHTED or REGISTERED)
    intensity : intensity measurement of the lidar
    r : red value
    g : green value
    b : blue value
    transform_state: status of the point.
        Initially it will be RAW (relative to lidar). x, y,z should be zero.
        After boresight is applied, it will be BORESIGHTED (relative to imu). x, y,z should be zero.
        After the point is registered to an sbet sample, it will be REGISTERED (relative to UTM). x,y,z values will now be populated
    */

    enum transform_state_t {
        RAW = 0,
        BORESIGHTED,
        REGISTERED
    };

    struct point_t {
        double time;
        double x;
        double y;
        double z;
        double x_relative;
        double y_relative;
        double z_relative;
        uint16_t r;
        uint16_t g;
        uint16_t b;
        double intensity;
        transform_state_t transform_state;
    };

    //Minimal subset struct of point_t, for external use to more efficienctly communicate with the HAL
    //using UDP or reader/writer queues. Used for Devkit Lite customers.
    struct point_min_t {
        double time;
        double x;
        double y;
        double z;
        double intensity;

        //Implicit conversion from point_min_t to point_t;
        operator point_t() {
            point_t point;
            point.time = time;
            point.x_relative = x;
            point.y_relative = y;
            point.z_relative = z;
            point.intensity = intensity;
            return point;
        }
    };
   
    ///////////////////////////
    /// Point IO //////////////
    ///////////////////////////

    inline point_t line_to_point_record(string line) {
        point_t point;
        vector<float> lineData;
        stringstream lineStream(line);

        // Process the line into the values
        lineStream >> point.x >> point.y >> point.z >> point.intensity;
        return point;
    }

    /*
     * reads a pts file from disk
     */
    inline void read_points(string pc_filename, vector<point_t> &points) {
        // Define variables
        points.clear();
        ifstream infile(pc_filename.c_str());
        string line;
        point_t point;
        // Read one line at a time into the variable line:
        while(getline(infile, line)) {
            point = line_to_point_record(line);
            points.push_back(point);
        }
    }


    // Same as read_points, but operates on in-memory strings rather than file paths
    inline vector<point_t> read_points_str(string points_str) {
        // Read one line at a time from points_str
        vector<point_t> points;
        std::istringstream iss(points_str);
        for (string line; getline(iss, line); ) {
            point_t point = line_to_point_record(line);
            points.push_back(point);
        }
        return points;
    }


    // Write the relative points to disk
    inline void write_relative_points(string file_path, vector<point_t>& points) {
        FILE * myfile;
        myfile = fopen (file_path.c_str(),"w");


        for (unsigned int i=0; i<points.size(); i++) {

            fprintf(myfile, "%10.2f %10.2f %10.2f %10.1f\n",
                     points[i].x_relative,
                     points[i].y_relative,
                     points[i].z_relative,
                     points[i].intensity);
        }

        fclose(myfile);
    }

}
#endif
