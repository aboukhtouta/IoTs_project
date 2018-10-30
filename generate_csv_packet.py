import os,sys
import numpy as np
import csv
import argparse
input="csv_results"
output="IoT_CSVs"

"python generate_csv_packet.py -i csv_results -o IoT_CSVs -n 2"
"python generate_csv_packet.py -i csv_results_5 -o IoT_CSVs -n 12"
"python generate_csv_packet.py -i csv_results_offset -o IoT_CSVs_offset -n 12"

def resource(filename):
	cwd = os.path.dirname(os.path.realpath(__file__))
	return os.path.join(cwd, filename)
	
def main():

	parser = argparse.ArgumentParser(description='generate IoTs CSVs')
	parser.add_argument('-i','--input', nargs='?', default ='./csv_results', help='path to parsed traces of IoTs')
	parser.add_argument('-o','--output', nargs='?', default ='./IoT_CSVs', help='path to store models')
	#parser.add_argument('-m','--mode', nargs='?', default=0, type= int, choices=[0,1], help='0 for static, 1 for dynamic')
	parser.add_argument('-n','--number', nargs='?', type=int, default=2, help='number of packets')

	if len(sys.argv)>1:
		args = parser.parse_args()
		pat = resource(args.input)
		out = resource(output+"_offset_"+str(args.number))
		os.mkdir(out)
		for item in sorted(os.listdir(pat)):
			dir=os.path.join(pat,item)
			if os.path.isdir(dir):
				with open(os.path.join(out,item+".csv"),"wb") as c:
					wr = csv.writer(c)
					for f in os.listdir(dir):
						x = np.genfromtxt(os.path.join(dir,f), delimiter='\t',usecols = range(0,23))
						if x.shape[0]%args.number ==0:
							for i in range(0,x.shape[0]/args.number):
								arr=x[i*args.number:(i+1)*args.number,:].tolist()
								flatten = [j for k in arr for j in k]
								wr.writerow(flatten)
						else:
							for i in range(0,int(x.shape[0]/args.number)+1):
								arr=x[i*args.number:(i+1)*args.number,:].tolist()
								flatten = [j for k in arr for j in k]
								if i==int(x.shape[0]/args.number):
									pad = [0] * ((args.number*23)-len(flatten))
									flatten.extend(pad)
								wr.writerow(flatten)
					#sys.exit(1)

if __name__=="__main__":
	main()