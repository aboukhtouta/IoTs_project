import numpy as np
import os,sys
from sklearn.cross_validation import train_test_split
from sklearn.grid_search import GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import pickle
import argparse
import time

'''python classification_IoTs.py -i IoT_CSVs_12 -o pickles -m 0 -d results.csv'''

def resource(filename):
	cwd = os.path.dirname(os.path.realpath(__file__))
	return os.path.join(cwd, filename)

def main():

	parser = argparse.ArgumentParser(description='Classification of IoTs CSVs')
	parser.add_argument('-i','--input', nargs='?', default ='./csvs', help='path to streaming folder')
	parser.add_argument('-o','--output', nargs='?', default ='./pickles', help='path to store models')
	parser.add_argument('-m','--mode', nargs='?', default=0, type= int, choices=[0,1], help='0 for unbalanced, 1 for balanced')
	parser.add_argument('-d','--dump', nargs='?', default='results.csv', help='path to dump stats')

	if len(sys.argv)>1:
		args = parser.parse_args()
		pat = resource(args.input)
		picks = resource(args.output)+"_"+pat[-2:]
		os.mkdir(picks)
		all_files=sorted(os.listdir(pat))
		cpt=0
		cpt1=1
		ests = [i*10 for i in range(1,11)]
		depths = [i for i in range(2,11)]
		param_grid = {'n_estimators': ests,'max_depth': depths}
		with open(resource(args.dump),"wb") as d:
			for item in all_files:
				if cpt1==15:
					data = np.genfromtxt(os.path.join(pat, item), delimiter=',')
					labels=[1]*(data.shape[0])
					s=int(round(float(data.shape[0])/26)) #number of samples to pick from other devices
					#sys.exit(1)
					cpt=0
					aggr=None
					for f in all_files:
						if f!=item:
							rest=np.genfromtxt(os.path.join(pat, f), delimiter=',')
							if args.mode ==1:
								idx = np.random.randint(10, size=s)
								rest=rest[idx,:]
							if cpt==0:
								aggr=rest
								cpt=cpt+1
							else:
								aggr=np.concatenate((aggr, rest), axis=0)
					labels_rest=[0]*aggr.shape[0]
					x=np.concatenate((data, aggr), axis=0)
					labels.extend(labels_rest)
					#x_train,x_test,y_train,y_test = train_test_split(x,labels,test_size=0.3,random_state=42)
					#rf=RandomForestClassifier(n_estimators=100,oob_score=True)
					#predicted =rf.predict(x_test)
					#accuracy = accuracy_score(y_test,predicted)
					#l=item[:-4]+","+str(rf.oob_score_)+","+str(accuracy)+"\n"
					#rf.fit(x_train,y_train)
					t=time.time()
					rf = RandomForestClassifier()
					grid_clf = GridSearchCV(rf, param_grid, cv=20, n_jobs = -1)
					grid_clf.fit(x, labels)
					t=time.time()-t
					print t
					print item[:-4]
					l=item[:-4]+"|"+str(grid_clf. best_params_)+"|"+str(grid_clf.grid_scores_)+"\n"
					d.write(l)
					pickle.dump(grid_clf, open(os.path.join(picks, item[:-4]+".pk"), 'wb'))
					cpt1=cpt1+1
				else:
					cpt1=cpt1+1
	else:
		print "Please refer to the following help listing ..."
		parser.print_help()
		sys.exit(1)

if __name__=="__main__":
	main()