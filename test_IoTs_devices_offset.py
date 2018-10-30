import numpy as np
import os,sys
from sklearn.cross_validation import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import pickle

p="pickles_12_offset"
csvs="IoT_CSVs_offset_12"

all_files=sorted(os.listdir(csvs))
all_pickles=sorted(os.listdir(p))

for model in all_pickles:
	cpt=0
	aggr=None
	labels=[]
	for item in all_files:
		if item!=model[:-3]+".csv":
			data = np.genfromtxt(csvs+"\\"+item, delimiter=',')
			if cpt==0:
				aggr=data
				cpt=cpt+1
			else:
				aggr=np.concatenate((aggr, data), axis=0)
			labels.extend([0]*(data.shape[1]))
		else:
			data1 = np.genfromtxt(csvs+"\\"+item, delimiter=',')
			if cpt==0:
				aggr=data1
				cpt=cpt+1
			else:
				aggr=np.concatenate((aggr, data1), axis=0)
			labels.extend([1]*(data1.shape[1]))
	labels=[0]*(aggr.shape[0])	
	loaded_model = pickle.load(open(p+"\\"+model, 'rb'))
	result = loaded_model.best_estimator_.score(aggr, labels)
	print model[:-3]
	print result