#!/usr/bin/env python
import cv2
import numpy as np
import sys,os
import json
import matplotlib.pyplot as plt
import copy

def get_image_with_bounding_box(img, outlines):
    # returns 

    img_bb = copy.deepcopy(img)

    for item in outlines:
        cv2.rectangle(img_bb, (item[0][0],item[0][1]), (item[2][0], item[2][1]), [0,255,0], 3)

    return img_bb

def get_cropped_img(img, outline, buffer_scale=1):
    # create a cropped image. larger buffer for more general

    assert(buffer_scale>=1)

    x_diff = outline[2][1] - outline[0][1]
    y_diff = outline[2][0] - outline[0][0]

    x_min = int(outline[0][1] - (buffer_scale-1)/2 * x_diff)
    x_max = int(outline[2][1] + (buffer_scale-1)/2 * x_diff)

    y_min = int(outline[0][0] - (buffer_scale-1)/2 * y_diff)
    y_max = int(outline[2][0] + (buffer_scale-1)/2 * y_diff)

    return img[x_min:x_max, y_min:y_max]

def load_signals(path):
    # Load the signal json
    with open(path) as json_data:
        signal_outlines = json.load(json_data)
    return signal_outlines

def get_frame_paths(directory):
    # Load list of frames
    frames = os.listdir(directory)
    frames.sort()
    return frames

def process_image(img, outlines, show_images):

    # Get image with bounding boxes
    img_bb = get_image_with_bounding_box(img, outlines)

    # Get cropped image
    img_cropped = get_cropped_img(img, outlines[0], 1)
    img_cropped_buffered = get_cropped_img(img, outlines[0], 1.2)

    # TODO: extract state of the signal (green or red)
    is_green = True

    if show_images:
        # Original image
        plt.imshow(img)
        plt.title("Image Original")
        plt.show()

        # Bounding Box image
        plt.imshow(img_bb)
        plt.title("Image Bounding Box")
        plt.show()

        # Cropped image
        plt.imshow(img_cropped)
        plt.title("Image cropped")
        plt.show()

        # Cropped image
        plt.imshow(img_cropped_buffered)
        plt.title("Image cropped buffered")
        plt.show()

    return is_green

if __name__ == '__main__':

    # path = "/home/scott/Downloads/frame_01623.png"
    unannotated_directory_path = "frames/"
    signal_outline_path = 'signal_outlines.json'
    starting_frame = 500
    ending_frame = 500
    show_images = True

    # Get signal outlines dictionary
    # key: frame name, value : list of pixel ranges for the signal
    signal_outlines = load_signals(signal_outline_path)
    
    # Get signal outlines dictionary
    # key: frame name, value : array of pixel ranges for the signal
    frame_names_unannotated = get_frame_paths(unannotated_directory_path)

    # Clip the frame
    frame_names_unannotated = frame_names_unannotated[starting_frame:ending_frame+1]
    
    # Iterate through the frames and process
    for frame_name in frame_names_unannotated:
        # Read in image and get the outline
        path = unannotated_directory_path + frame_name
        img = cv2.imread(path)
        img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)#because opencv and matplotlib use different standards
        outlines = signal_outlines[frame_name]

        # Process image
        is_green = process_image(img, outlines, show_images)
