#!/usr/local/bin/python

# Author: Anatoly Karp, Internet2 (2002)

# build a histogram of one-way delays from a bucket file
# usage: buckets.py <bucket_file>

import struct, sys, os
import Gnuplot, Gnuplot.funcutils

from stat import *
from Numeric import *

NUM_LOW = 50000
NUM_MID  = 1000
NUM_HIGH = 49900

MAX_BUCKET =  (NUM_LOW + NUM_MID + NUM_HIGH - 1)

CUTOFF_A = (-50.0)
CUTOFF_B = 0.0
CUTOFF_C = 0.1
CUTOFF_D = 50.0

mesh_low = (CUTOFF_B - CUTOFF_A)/NUM_LOW;
mesh_mid = (CUTOFF_C - CUTOFF_B)/NUM_MID;
mesh_high = (CUTOFF_D - CUTOFF_C)/NUM_HIGH;

def index2pt(index):
    if index < 0 or index > MAX_BUCKET:
        print 'Index over-run: index = ', index
        exit(1)
        
    if index <= NUM_LOW:
        return CUTOFF_A + index * mesh_low
    if index <= NUM_LOW + NUM_MID:
        return CUTOFF_B + (index - NUM_LOW) * mesh_mid
    return CUTOFF_C + (index - NUM_LOW - NUM_MID) * mesh_high
        
try:
    datafile = open(sys.argv[1], "r")
except:
    print 'Could not open file ', argv[1]
    exit(1)

size = os.stat(sys.argv[1])[ST_SIZE]
if size%6 != 0:
    print 'FATAL: Non-integer number of buckets'
    sys.exit(1)

p = []
q = []

i = 0
while i < size / 6:
    data = datafile.read(6)
    index, count = struct.unpack('IH', data)
    print "index = ", index, " count = ", count, "point = ", index2pt(index)
    p.append(index2pt(index))
    q.append(count)
    i = i + 1

g = Gnuplot.Gnuplot(debug=1)

x = array(p, Float)
y1 = array(q, Float)

d = Gnuplot.Data(x, y1,
                 with='histeps')
g.title('Histogram of one-way delays')
g.xlabel('seconds')
g.ylabel('bin count')

g.plot(d)

raw_input('Please press return to continue...\n')
