import numpy as np
from sklearn.cluster import KMeans

test_data = np.random.rand(50,3)
test_data = test_data.round(decimals=2)
test_data2 = [[0,0,0], [.75,.75,.75]]*45
test_data2 += [[.20,.20,.20]]*10

print(test_data2)
print(len(test_data2))
c_array = "{"
for row in test_data2:
    row_str = "{"
    for coord in row:
        row_str += str(coord)+','
    row_str = row_str[:-1] + "}"
    c_array += row_str + ','
c_array = c_array[:-1]+'}'
print(c_array)
kmeans = KMeans(n_clusters=3, random_state=0).fit(test_data2)
print(kmeans.cluster_centers_)