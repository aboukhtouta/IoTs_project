from mpl_toolkits.mplot3d import Axes3D
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import sys,os
import randomcolor
import pickle

df = pd.read_csv('results_12_new.csv', sep=' ', names=["Mean", "STD", "N_Estimators","Depth"])
devs=["Aria","D-LinkCam","D-LinkDayCam","D-LinkDoorSensor","D-LinkHomeHub","D-LinkSensor","D-LinkSiren","D-LinkSwitch","D-LinkWaterSensor","EdimaxCam","EdimaxPlug1101W","EdimaxPlug2101W","EdnetCam","EdnetGateway","HomeMaticPlug","HueBridge","HueSwitch","Lightify","MAXGateway","SmarterCoffee","TP-LinkPlugHS100","TP-LinkPlugHS110","WeMoInsightSwitch","WeMoLink","WeMoSwitch","Withings","iKettle2"]
accuracies=df["Mean"].tolist()
estimators=df["N_Estimators"].tolist()
depths=df["Depth"].tolist()
rand_color = randomcolor.RandomColor()
colors=rand_color.generate(count=27)
with open('colors.pk', 'wb') as handle:
    pickle.dump(colors, handle)

#print colors
#print colors[3:6]
#sys.exit(1)
fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')
ax.set_xlabel('Esptimators')
ax.set_ylabel('Depth')
ax.set_zlabel('Mean Accuracy')

cpt=0
off=0
for item in devs:
	x=estimators[off:off+90]
	y=depths[off:off+90]
	z=accuracies[off:off+90]
	ax.scatter(x, y, z, c=colors[cpt], marker='x', label=item)
	off=off+90
	cpt=cpt+1

box = ax.get_position()
ax.set_position([box.x0, box.y0, box.width * 0.8, box.height])
ax.legend(loc='center left', bbox_to_anchor=(1, 0.5))

plt.show()