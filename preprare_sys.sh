#!/bin/sh

echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
sudo sh -c "echo core > /proc/sys/kernel/core_pattern"
cd /sys/devices/system/cpu
echo performance | sudo tee cpu*/cpufreq/scaling_governor

