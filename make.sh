#!/bin/bash
sudo apt install -y build-essential bc bison flex libelf-dev libssl-dev libncurses5-dev

cd linux_6.1_mod

cp /boot/config-$(uname -r) .config

replace_string() {
    search_string="$1"
    replace_string="$2"
    input_file="$3"
    output_file="$4"

    echo "" >> $output_file

    while IFS='' read -r line || [[ -n "$line" ]]; do
        if [[ $line == *"$search_string"* ]]; then
            line="$replace_string"
        fi
        echo "$line" >> "$output_file"
    done < "$input_file"
}

replace_string "CONFIG_SYSTEM_TRUSTED_KEYS" 'CONFIG_SYSTEM_TRUSTED_KEYS=""' "./.config" "./temp1"
replace_string "CONFIG_DEBUG_INFO_BTF" 'CONFIG_DEBUG_INFO_BTF=n' "./temp1" "./temp2"

rm -rf ./.config
rm -rf ./temp1
mv ./temp2 ./.config

make localmodconfig
make -j$(nproc)
# sudo make modules_install
# sudo make install
# sudo reboot
