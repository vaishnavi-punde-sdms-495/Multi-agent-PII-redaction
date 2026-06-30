#image_utils
# def polygon_to_xyxy(polygon, img_w, img_h, padding=4):
    """Convert polygon points to XYXY rectangle format."""
    xs = [p[0] for p in polygon]
    ys = [p[1] for p in polygon]
    return [
        max(0, min(xs) - padding),
        max(0, min(ys) - padding),
        min(img_w, max(xs) + padding),
        min(img_h, max(ys) + padding)
    ]

def merge_nearby_boxes(boxes, x_gap=20, y_gap=8):
    """Merge boxes that are on the same line and close horizontally."""
    if not boxes:
        return boxes
    sorted_boxes = sorted(boxes, key=lambda b: (b[1], b[0]))
    merged = [sorted_boxes[0]]
    for box in sorted_boxes[1:]:
        last = merged[-1]
        same_line = abs(box[1] - last[1]) < y_gap
        close_x = box[0] - last[2] < x_gap
        if same_line and close_x:
            merged[-1] = [
                min(last[0], box[0]),
                min(last[1], box[1]),
                max(last[2], box[2]),
                max(last[3], box[3])
            ]
        else:
            merged.append(box)
    return merged

def expand_bbox(bbox, padding, img_w, img_h):
    """Expand bounding box with padding."""
    return [
        max(0, bbox[0] - padding),
        max(0, bbox[1] - padding),
        min(img_w, bbox[2] + padding),
        min(img_h, bbox[3] + padding)
    ]
