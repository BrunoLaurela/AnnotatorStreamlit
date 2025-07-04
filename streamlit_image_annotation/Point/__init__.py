import os
import streamlit.components.v1 as components
from streamlit.components.v1.components import CustomComponent

import streamlit as st
import streamlit.elements.image as st_image
from PIL import Image
import numpy as np
import matplotlib.pyplot as plt
from hashlib import md5
from streamlit_image_annotation import IS_RELEASE

from custom_image import image_to_url

if IS_RELEASE:
    absolute_path = os.path.dirname(os.path.abspath(__file__))
    build_path = os.path.join(absolute_path, "frontend/build")
    _component_func = components.declare_component("st_point", path=build_path)
else:
    _component_func = components.declare_component("st_point", url="http://localhost:3000")

def get_colormap(label_names, colormap_name='gist_rainbow'):
    colormap = {} 
    cmap = plt.get_cmap(colormap_name)
    for idx, l in enumerate(label_names):
        rgb = [int(d) for d in np.array(cmap(float(idx)/len(label_names)))*255][:3]
        colormap[l] = ('#%02x%02x%02x' % tuple(rgb))
    return colormap

def pointdet(image, label_list, points=None, labels=None, height=512, width=512, manual_scale=-1, point_width=3, use_space=False, 
             key=None, mode=None, label=None, mask_path=None, contour_path=None, m_transparency=0.5, c_transparency=1, zoom=2, colors=None) -> CustomComponent:

    if manual_scale != -1:
        scale = 1/manual_scale
    else:
        original_image_size = image.size
        image.thumbnail(size=(width, height))
        resized_image_size = image.size
        scale = original_image_size[0]/resized_image_size[0]
    
    image_url = image_to_url(image, image.size[0], True, "RGBA", "PNG", f"point-{md5(image.tobytes()).hexdigest()}-{key}")
    if image_url.startswith('/'):
        image_url = image_url[1:]

    if mask_path is not None:
        mask = Image.open(mask_path)
        mask_url = image_to_url(mask, image.size[0], True, "RGBA", "PNG", f"point-{md5(mask.tobytes()).hexdigest()}-{key}")
        if mask_url.startswith('/'):
            mask_url = mask_url[1:]
    else:
        m_transparency = 0
        mask_url=image_url
    
    if contour_path is not None:
        contour = Image.open(contour_path)
        contour_url = image_to_url(contour, image.size[0], True, "RGBA", "PNG", f"point-{md5(contour.tobytes()).hexdigest()}-{key}")
        if contour_url.startswith('/'):
            contour_url = contour_url[1:]
    else:
        c_transparency = 0
        contour_url=image_url

    # Use provided colors or generate a colormap
    if colors:
        color_map = {label: color for label, color in zip(label_list, colors)}
    else:
        color_map = get_colormap(label_list, colormap_name='gist_rainbow')

    points_info = [{'point': [b/scale for b in item[0]], 'label_id': item[1], 'label': label_list[item[1]]} for item in zip(points, labels)]
    component_value = _component_func(image_url=image_url, mask_url=mask_url, contour_url=contour_url, image_size=image.size, label_list=label_list, points_info=points_info, 
        color_map=color_map, point_width=point_width, use_space=use_space, key=key, mode=mode, label=label, zoom=zoom, mask_trans=m_transparency, contour_trans=c_transparency)
    if component_value is not None:
        component_value = [{'point': [b*scale for b in item['point']], 'label_id': item['label_id'], 'label': item['label']} for item in component_value]
    return component_value

if not IS_RELEASE:
    from glob import glob
    import pandas as pd
    label_list = ['deer', 'human', 'dog', 'penguin', 'framingo', 'teddy bear']
    image_path_list = glob('image/*.jpg')
    if 'result_dict' not in st.session_state:
        result_dict = {}
        for img in image_path_list:
            result_dict[img] = {'points': [[0,0],[50,150], [200,200]],'labels':[0,3,4]}
        st.session_state['result_dict'] = result_dict.copy()


    num_page = st.slider('page', 0, len(image_path_list)-1, 0)
    target_image_path = image_path_list[num_page]
    new_labels = pointdet(image_path=target_image_path, 
                           label_list=label_list, 
                           points=st.session_state['result_dict'][target_image_path]['points'],
                           labels=st.session_state['result_dict'][target_image_path]['labels'],
                           point_width=3, use_space=True, key=target_image_path)

    if new_labels is not None:
        st.session_state['result_dict'][target_image_path]['points'] = [v['point'] for v in new_labels]
        st.session_state['result_dict'][target_image_path]['labels'] = [v['label_id'] for v in new_labels]
    st.json(st.session_state['result_dict'])