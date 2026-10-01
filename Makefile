# Makefile -- Tarea 1 2026
#
#   make all       -> compila pcap2bin, exact_hh y tarea1
#   make run       -> corre los experimentos del enunciado
#   make run-plots -> solo regenera figuras y tablas (no re-corre binarios)
#   make clean     -> limpia binarios y salidas

CXX      ?= g++
CXXFLAGS ?= -O2 -march=native -std=c++17 -Wall -Wextra -Wno-unused-parameter
PYTHON   ?= python3

BINS = pcap2bin exact_hh tarea1

.PHONY: all run run-plots clean help

all: $(BINS)

pcap2bin: pcap2bin.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

exact_hh: exact_hh.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

tarea1: tarea1.cpp sketches.hpp
	$(CXX) $(CXXFLAGS) -o $@ tarea1.cpp

run: all
	$(PYTHON) run_experiments.py --seed 42

run-plots: all
	$(PYTHON) run_experiments.py --only-plots

clean:
	rm -f $(BINS) *.o
	rm -rf out results figures
	rm -f traza_ddos.bin traza_scan.bin gt_ddos.json gt_scan.json

help:
	@echo "make all       : compila pcap2bin, exact_hh, tarea1"
	@echo "make run       : corre los experimentos del enunciado"
	@echo "make run-plots : solo regenera figuras y tablas"
	@echo "make clean     : limpia binarios y salidas"