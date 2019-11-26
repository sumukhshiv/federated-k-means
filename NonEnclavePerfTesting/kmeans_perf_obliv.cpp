#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include "kmeans_perf_obliv.h"
#include <algorithm>


#define sqr(x) ((x)*(x))

#define MAX_CLUSTERS 16

#define MAX_ITERATIONS 100

#define BIG_double (100000000)

void fail_obliv(char *str)
  {
      exit(-1);
  }
  
double calc_distance_obliv(int dim, double *p1, double *p2)
  {
    double distance_sq_sum = 0;
    
    for (int ii = 0; ii < dim; ii++)
      distance_sq_sum += sqr(p1[ii] - p2[ii]);

    return distance_sq_sum;
    
  }

void calc_all_distances_obliv(int dim, int n, int k, double *X, double *centroid, double *distance_output)
  {
    for (int ii = 0; ii < n; ii++) // for each point
      for (int jj = 0; jj < k; jj++) // for each cluster
        {
         // calculate distance between point and cluster centroid
          distance_output[ii*k + jj] = calc_distance_obliv(dim, &X[ii*dim], &centroid[jj*dim]);
        }
  }
  
double calc_total_distance_obliv(int dim, int n, int k, double *X, double *centroids, int *cluster_assignment_index)
 // NOTE: a point with cluster assignment -1 is ignored
  {
    double tot_D = 0;
    
   // for every point
    for (int ii = 0; ii < n; ii++)
      {
       // which cluster is it in?
        int active_cluster = cluster_assignment_index[ii];
        
       // sum distance
       //OBLIV-EDIT
        int cond = active_cluster != -1;
        int exec = calc_distance_obliv(dim, &X[ii*dim], &centroids[active_cluster*dim]);
        tot_D = tot_D * (1 - cond) + (exec + tot_D) * (cond);
      }
      
    return tot_D;
  }

void choose_all_clusters_from_distances_obliv(int dim, int n, int k, double *distance_array, int *cluster_assignment_index)
  {
   // for each point
    for (int ii = 0; ii < n; ii++)
      {
        int best_index = -1;
        double closest_distance = BIG_double;
        
       // for each cluster
        for (int jj = 0; jj < k; jj++)
          {
           // distance between point and cluster centroid
           
            double cur_distance = distance_array[ii*k + jj];
            int cond = cur_distance < closest_distance;

            best_index = (cond*jj) + ((1-cond)*best_index);
            closest_distance = (double)((cond*cur_distance)+ ((1.0-cond)*closest_distance));
          }

       // record in array
        cluster_assignment_index[ii] = best_index;
      }
  }

void calc_cluster_centroids_obliv(int dim, int n, int k, double *X, int *cluster_assignment_index, double *new_cluster_centroid)
  {
    //Obliviously fix NaN cluster centroids by adding a padding of 1 when a cluster has 0 members
    int temp_cluster_member_count[MAX_CLUSTERS];
    int cluster_member_count[MAX_CLUSTERS];
    double temp_cluster_centroid[dim*k];
   // initialize cluster centroid coordinate sums to zero
    for (int ii = 0; ii < k; ii++) 
      {
        temp_cluster_member_count[ii] = 0;
        
        for (int jj = 0; jj < dim; jj++)
          //new_cluster_centroid[ii*dim + jj] = 0;
          temp_cluster_centroid[ii*dim + jj] = 0;
     }

   // sum all points
   // for every point
    for (int ii = 0; ii < n; ii++)
      {
       // which cluster is it in?
        int active_cluster = cluster_assignment_index[ii];

       // update count of members in that cluster
        temp_cluster_member_count[active_cluster]++;
        
       // sum point coordinates for finding centroid
        for (int jj = 0; jj < dim; jj++)
          //new_cluster_centroid[active_cluster*dim + jj] += X[ii*dim + jj];
          temp_cluster_centroid[active_cluster*dim + jj] += X[ii*dim + jj];

      }
    
    for (int i = 0; i < k; i++){
      int cond = temp_cluster_member_count[i] == 0;
      cluster_member_count[i] = cond*(temp_cluster_member_count[i]+1) + (1-cond)*temp_cluster_member_count[i];
    }
      
      
   // now divide each coordinate sum by number of members to find mean/centroid
   // for each cluster
    for (int ii = 0; ii < k; ii++) 
      {
        if (cluster_member_count[ii] == 0) {

        }
   //       printf("WARNING: Empty cluster %d! \n", ii);
          
       // for each dimension
       int cond = temp_cluster_member_count[ii] == 0;
        for (int jj = 0; jj < dim; jj++){
          new_cluster_centroid[ii*dim + jj] = cond*new_cluster_centroid[ii*dim + jj] + 
          (1-cond)*temp_cluster_centroid[ii*dim + jj]/cluster_member_count[ii];
        }
          //new_cluster_centroid[ii*dim + jj] /= cluster_member_count[ii];  /// XXXX will divide by zero here for any empty clusters!

      }
  }

void get_cluster_member_count_obliv(int n, int k, int *cluster_assignment_index, int *cluster_member_count)
  {
   // initialize cluster member counts
    for (int ii = 0; ii < k; ii++) 
      cluster_member_count[ii] = 0;
  
   // count members of each cluster    
    for (int ii = 0; ii < n; ii++)
      cluster_member_count[cluster_assignment_index[ii]]++;
  }

void update_delta_score_table_obliv(int dim, int n, int k, double *X, int *cluster_assignment_cur, double *cluster_centroid, int *cluster_member_count, double *point_move_score_table, int cc)
  {
   // for every point (both in and not in the cluster)
    for (int ii = 0; ii < n; ii++)
      {
        double dist_sum = 0;
        for (int kk = 0; kk < dim; kk++)
          {
            double axis_dist = X[ii*dim + kk] - cluster_centroid[cc*dim + kk]; 
            dist_sum += sqr(axis_dist);
          }
          
        double mult = ((double)cluster_member_count[cc] / (cluster_member_count[cc] + ((cluster_assignment_cur[ii]==cc) ? -1 : +1)));

        point_move_score_table[ii*dim + cc] = dist_sum * mult;
      }
  }
  
  
void  perform_move_obliv(int dim, int n, int k, double *X, int *cluster_assignment, double *cluster_centroid, int *cluster_member_count, int move_point, int move_target_cluster)
  {
    int cluster_old = cluster_assignment[move_point];
    int cluster_new = move_target_cluster;
  
   // update cluster assignment array
    cluster_assignment[move_point] = cluster_new;
    
   // update cluster count array
    cluster_member_count[cluster_old]--;
    cluster_member_count[cluster_new]++;
    
   // update centroid array
    for (int ii = 0; ii < dim; ii++)
      {
        cluster_centroid[cluster_old*dim + ii] -= (X[move_point*dim + ii] - cluster_centroid[cluster_old*dim + ii]) / cluster_member_count[cluster_old];
        cluster_centroid[cluster_new*dim + ii] += (X[move_point*dim + ii] - cluster_centroid[cluster_new*dim + ii]) / cluster_member_count[cluster_new];
      }
  }  
  
void cluster_diag_obliv(int dim, int n, int k, double *X, int *cluster_assignment_index, double *cluster_centroid) {
  int cluster_member_count[MAX_CLUSTERS];
  get_cluster_member_count_obliv(n, k, cluster_assignment_index, cluster_member_count);
  
  // printf("  Final clusters \n");
  for (int ii = 0; ii < k; ii++) {
    char* hello_world = (char*)malloc(150 * sizeof(char));
    snprintf(hello_world, 150, " cluster %d:     members: %8d, centroid (%.3f %.3f %.3f) \n", ii, cluster_member_count[ii], cluster_centroid[ii*dim + 0], cluster_centroid[ii*dim + 1], cluster_centroid[ii*dim + 2]);
    printf(hello_world);
  }
}

void copy_assignment_array_obliv(int n, int *src, int *tgt)
  {
    for (int ii = 0; ii < n; ii++)
      tgt[ii] = src[ii];
  }
  
int assignment_change_count_obliv(int n, int a[], int b[])
  {
    int change_count = 0;
    for (int ii = 0; ii < n; ii++) {
      int cond = (a[ii] != b[ii]);
      change_count = cond*(change_count+1) + (1-cond)*(change_count);
    }
  return change_count;
  }

void kmeans_obliv(
            int  dim,		                     // dimension of data 

            double *X,                        // pointer to data
            int   n,                         // number of elements
            
            int   k,                         // number of clusters
            double *cluster_centroid,         // initial cluster centroids
            int   *cluster_assignment_final  // output
           )
  {
    double *dist                    = (double *)malloc(sizeof(double) * n * k);
    int   *cluster_assignment_cur  = (int *)malloc(sizeof(int) * n);
    int   *cluster_assignment_prev = (int *)malloc(sizeof(int) * n);
    double *point_move_score        = (double *)malloc(sizeof(double) * n * k);
    
    
    if (!dist || !cluster_assignment_cur || !cluster_assignment_prev || !point_move_score)
      fail_obliv("Error allocating dist arrays");
    
   // initial setup  
    calc_all_distances_obliv(dim, n, k, X, cluster_centroid, dist);
    choose_all_clusters_from_distances_obliv(dim, n, k, dist, cluster_assignment_cur);
    copy_assignment_array_obliv(n, cluster_assignment_cur, cluster_assignment_prev);

   // BATCH UPDATE
    double prev_totD = BIG_double;
    int batch_iteration = 0;
    while (batch_iteration < MAX_ITERATIONS) {
    // update cluster centroids
    calc_cluster_centroids_obliv(dim, n, k, X, cluster_assignment_cur, cluster_centroid);
    // see if we've failed to improve
    double totD = calc_total_distance_obliv(dim, n, k, X, cluster_centroid, cluster_assignment_cur);
    int cond = (totD > prev_totD);
    //  int *cluster_assignment_cur = (cluster_assignment_prev)*cond + (cluster_assignment_cur)*(1-cond);
    for (int i = 0; i < n; i++) {
      cluster_assignment_cur[i] = (cluster_assignment_prev[i])*cond + (cluster_assignment_cur[i])*(1-cond);
    }
    calc_cluster_centroids_obliv(dim, n, k, X, cluster_assignment_cur, cluster_centroid);
    // save previous step
    copy_assignment_array_obliv(n, cluster_assignment_cur, cluster_assignment_prev);
    
    // move all points to nearest cluster
    calc_all_distances_obliv(dim, n, k, X, cluster_centroid, dist);
    choose_all_clusters_from_distances_obliv(dim, n, k, dist, cluster_assignment_cur);
    
    prev_totD = totD;
    batch_iteration++;
}

cluster_diag_obliv(dim, n, k, X, cluster_assignment_cur, cluster_centroid);
      
   // write to output array
    copy_assignment_array_obliv(n, cluster_assignment_cur, cluster_assignment_final);    
    
    free(dist);
    free(cluster_assignment_cur);
    free(cluster_assignment_prev);
    free(point_move_score);
  }  