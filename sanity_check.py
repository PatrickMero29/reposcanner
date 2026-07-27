import os
import pickle

def run(user_input):
    os.system("echo " + user_input)

def load(data):
    return pickle.loads(data)

