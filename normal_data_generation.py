import numpy as np
from sklearn.cluster import KMeans

num_points = 960*4 # Change this for more/less data points
dim = 3
my_loc = 0.0;

# open(str(num_points)+"_points.txt", 'w').close()

for i in range(3):
    if i == 0:
        my_loc = 0.3
    if i == 1:
        my_loc = 0.6
    if i == 2:
        my_loc = 0.9

    test_data2 = []
    for _ in range(num_points):
        test_data2 += [[np.random.normal(loc=my_loc, scale=0.01) for _ in range(dim)]]

    c_array = "{"
    for row in test_data2:
        row_str = "{"
        for coord in row:
            row_str += str(coord)+','
        row_str = row_str[:-1] + "}"
        c_array += row_str + ','
    c_array = c_array[:-1]+'}'

    # with open(str(num_points)+"_points.txt", "a") as myfile:
    #     myfile.write(c_array)
    #     myfile.write('\n------------------------------\n')

    print(c_array)
    print('------------------------------')


# kmeans = KMeans(n_clusters=3, random_state=0).fit(test_data2)
# print(kmeans.cluster_centers_)

