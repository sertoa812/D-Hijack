#!/bin/bash
# china or aboard
dataset="aboard-4"
ite_data_folder="../$dataset-DATASET/ite_data_dealed"
resolver_data_folder="../$dataset-DATASET/resolver_data"
# 指定文件夹路径
target_string="{DATE}"
dataset_string="{REAL_DATASET}"
raw_config_file="./raw_config"

for file in "$ite_data_folder"/*; do
    # 提取文件名（去掉路径和扩展名）
    filename=$(basename "$file")
    name_without_extension="${filename%.*}"
    date=${name_without_extension:2}
    new_config_file='./config'

    cp "$raw_config_file" "$new_config_file"
    sed -i "s/$dataset_string/$dataset/g" "$new_config_file"
    sed -i "s/$target_string/$date/g" "$new_config_file"

    python ./1.RBLine-IP.py
    python ./2.1.get_cdn.py
    python ./2.2.cdn_filter.py
    python ./2.3.get_certs.py
    python ./3.RBLine_Certs.py
    python ./6.produce_result.py

    sleep 5
    rm "$new_config_file"
done
