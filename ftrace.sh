#!/bin/bash

TRACE_DIR=/sys/kernel/debug/tracing

# clear
echo 0 > $TRACE_DIR/tracing_on
echo > $TRACE_DIR/set_graph_function
echo > $TRACE_DIR/set_ftrace_filter
echo nop > $TRACE_DIR/current_tracer

# setting
echo function_graph > $TRACE_DIR/current_tracer
echo 5 > $TRACE_DIR/max_graph_depth
echo http_server_worker > $TRACE_DIR/set_graph_function

# execute
echo 1 > $TRACE_DIR/tracing_on
wget localhost:8081
echo 0 > $TRACE_DIR/tracing_on

cat $TRACE_DIR/trace > trace.txt