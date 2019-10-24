# Adapted from the wonderful kNN tutorial here:
# https://machinelearningmastery.com/tutorial-to-implement-k-nearest-neighbors-in-python-from-scratch/

import sys
import csv
import random
from cffi import FFI
from weakref import WeakKeyDictionary

global_weakkeydict = WeakKeyDictionary()

def loadDataset(filename, split, trainingSet=[], testSet=[], category_map={}):
    num_categories = 0
    with open(filename, 'r') as csvfile:
        lines = csv.reader(csvfile)
        dataset = list(lines)
        for x in range(len(dataset)-1):
            for y in range(len(dataset[x]) - 1):
                dataset[x][y] = float(dataset[x][y])
            try:
                dataset[x][-1] = category_map[dataset[x][-1]]
            except KeyError:
                category_map[dataset[x][-1]] = num_categories
                num_categories += 1
                dataset[x][-1] = category_map[dataset[x][-1]]
            if random.random() < split:
                trainingSet.append(dataset[x])
            else:
                testSet.append(dataset[x])
    return num_categories

def getAccuracy(test_set, predictions):
    correct = 0
    for x in range(len(test_set)):
        if test_set[x][-1] == predictions[x]:
            correct += 1
    return (correct/float(len(test_set))) * 100.0

def loadKNN(ffi):
    knn_module = ffi.dlopen(sys.argv[2])
    ffi.cdef("""
        typedef struct KNN_Entry {
          int category;
          unsigned int num_attributes;
          double *attributes;
        } KNN_Entry_t;
    """)
    ffi.cdef("""
        void knn(unsigned k, unsigned num_categories,
                 const KNN_Entry_t *training_set,
                 unsigned int training_set_size, KNN_Entry_t *test_set,
                 unsigned int test_set_size);
    """)
    return knn_module.knn

def runKNN(ffi, knn, k, num_categories, trainingSet, testSet):
    trainingEntries = ffi.new("KNN_Entry_t[]", len(trainingSet))
    for i in range(len(trainingSet)):
        attrs = ffi.new("double[]", len(trainingSet[i]) - 1)
        try:
            global_weakkeydict[trainingEntries].append(attrs)
        except KeyError:
            global_weakkeydict[trainingEntries] = [attrs]
        for j in range(len(trainingSet[i]) - 1):
            attrs[j] = trainingSet[i][j]
        trainingEntries[i].attributes = attrs
        trainingEntries[i].num_attributes = len(trainingSet[i]) - 1
        trainingEntries[i].category = trainingSet[i][-1]
    testEntries = ffi.new("KNN_Entry_t[]", len(testSet))
    for i in range(len(testSet)):
        attrs = ffi.new("double[]", len(testSet[i]) - 1)
        try:
            global_weakkeydict[testEntries].append(attrs)
        except KeyError:
            global_weakkeydict[testEntries] = [attrs]
        for j in range(len(testSet[i]) - 1):
            attrs[j] = testSet[i][j]
        testEntries[i].attributes = attrs
        testEntries[i].num_attributes = len(testSet[i]) - 1
    knn(3, num_categories, trainingEntries, len(trainingEntries),
                   testEntries, len(testEntries))
    predictions = []
    for x in range(len(testEntries)):
        predictions.append(testEntries[x].category)
    return predictions

def main():
    # prepare data
    trainingSet = []
    testSet = []
    category_map = {}
    split = 0.67 # approx. ratio of test set to training set
    num_categories = loadDataset(sys.argv[1], split, trainingSet, testSet,
                                 category_map)
    print('Training set size: ' + repr(len(trainingSet)))
    print('Test set size: ' + repr(len(testSet)))
    # generate predictions
    predictions=[]
    k = 3 # number of nearest neighbors
    ffi = FFI()
    knn = loadKNN(ffi)
    predictions = runKNN(ffi, knn, k, num_categories, trainingSet, testSet)
    accuracy = getAccuracy(testSet, predictions)
    print('Accuracy: ' + repr(accuracy) + '%')

main()
