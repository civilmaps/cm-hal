#!/bin/bash
wget https://s3-us-west-1.amazonaws.com/civilmaps-artifacts/webinar3/signal_outlines.json
wget https://s3-us-west-1.amazonaws.com/civilmaps-artifacts/webinar3/frames.zip
unzip frames.zip
mv frames_1 frames
