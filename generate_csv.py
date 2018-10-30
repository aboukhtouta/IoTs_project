import os,sys
import numpy as np
import csv
import argparse

def resource(filename):
	cwd = os.path.dirname(os.path.realpath(__file__))
	return os.path.join(cwd, filename)
	
def main:
	parser = argparse.ArgumentParser(description='CSV generator')
	parser.add_argument('-i','--input', nargs='?', default ='./csv_results', help='path to streaming folder')
	parser.add_argument('-o','--output', nargs='?', default ='./IoTs_CSVs', help='path to output folder')
	parser.add_argument('-n', '--nbr', nargs='?', default=12, type=int, choices=range(1,13), help='number of packets to generate a fingerprint')
	if len(sys.argv)>1:
		args = parser.parse_args()
		input=resource(args.input)
		output=resource(args.output)
		for item in sorted(os.listdir()):
			if os.path.isdir(input+os.sep+item):
				with open(output+os.sep+item+".csv","wb") as c:
					wr = csv.writer(c)
					for f in os.listdir(input+os.sep+item):
						x = np.genfromtxt(input+os.sep+item+os.sep+f, delimiter='\t',usecols = range(0,23))
						if x.shape[0]%args.nbr ==0:
							for i in range(0,x.shape[0]/args.nbr):
								arr=x[i*args.nbr:(i+1)*args.nbr,:].tolist()
								flatten = [j for k in arr for j in k]
								wr.writerow(flatten)
						else:
							for i in range(0,int(x.shape[0]/args.nbr)+1):
								arr=x[i*args.nbr:(i+1)*args.nbr,:].tolist()
								flatten = [j for k in arr for j in k]
								if i==int(x.shape[0]/args.nbr):
									pad = [0] * ((args.nbr * 23)-len(flatten))
									flatten.extend(pad)
								wr.writerow(flatten)
					#sys.exit(1)