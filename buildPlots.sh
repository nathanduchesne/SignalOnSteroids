#!/bin/sh

data_file_names=("rrc_receive_alice_spams_bob.txt" "rrc_send_alice_spams_bob.txt")
for file_name in ${data_file_names[@]}; do
# CLI args are data_file_name, plot_name, x_label, y_label, plot_title
    file_with_hierarchy="../../Report/Plots/BenchLogs/"$file_name
    python ../../Report/Plots/plot_from_data.py $file_with_hierarchy "../../Report/Plots/"${file_name%.txt*}".png" "nbr_msgs" "micro_seconds" ${file_name%.txt*}
done