// kmeans.c
// Ethan Brodsky
// October 2011

#include <math.h>
#include <stdlib.h>
#include <stdio.h>

#define sqr(x) ((x)*(x))

#define MAX_CLUSTERS 16

#define MAX_ITERATIONS 100

#define BIG_double (100000000)

void fail(char *str)
  {
    printf(str);
    exit(-1);
  }
  
double calc_distance(int dim, double *p1, double *p2)
  {
    double distance_sq_sum = 0;
    
    for (int ii = 0; ii < dim; ii++)
      distance_sq_sum += sqr(p1[ii] - p2[ii]);

    return distance_sq_sum;
    
  }

void calc_all_distances(int dim, int n, int k, double *X, double *centroid, double *distance_output)
  {
    for (int ii = 0; ii < n; ii++) // for each point
      for (int jj = 0; jj < k; jj++) // for each cluster
        {
         // calculate distance between point and cluster centroid
          distance_output[ii*k + jj] = calc_distance(dim, &X[ii*dim], &centroid[jj*dim]);
        }
  }
  
double calc_total_distance(int dim, int n, int k, double *X, double *centroids, int *cluster_assignment_index)
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
        int exec = calc_distance(dim, &X[ii*dim], &centroids[active_cluster*dim]);
        tot_D = tot_D * (1 - cond) + (exec + tot_D) * (cond);
      }
      
    return tot_D;
  }

void choose_all_clusters_from_distances(int dim, int n, int k, double *distance_array, int *cluster_assignment_index)
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
            // printf("COND %d\n", cond);
            // int tmp1 = jj;
            // double tmp2 = cur_distance;
            best_index = (cond*jj) + ((1-cond)*best_index);
            closest_distance = (double)((cond*cur_distance)+ ((1.0-cond)*closest_distance));
            // if (cur_distance < closest_distance)
            //   {
            //     // best_index = jj;
            //     closest_distance = (double)cur_distance;
            //   }

            // if (closest_distance - closest_distance1) {
            //   printf("CLOSEST DISTANCE %f, CLOSEST DISTANCE1 %f\n", closest_distance, closest_distance1);
            // }
            // closest_distance = closest_distance1;

          }

       // record in array
        cluster_assignment_index[ii] = best_index;
      }
  }

void calc_cluster_centroids(int dim, int n, int k, double *X, int *cluster_assignment_index, double *new_cluster_centroid)
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

void get_cluster_member_count(int n, int k, int *cluster_assignment_index, int *cluster_member_count)
  {
   // initialize cluster member counts
    for (int ii = 0; ii < k; ii++) 
      cluster_member_count[ii] = 0;
  
   // count members of each cluster    
    for (int ii = 0; ii < n; ii++)
      cluster_member_count[cluster_assignment_index[ii]]++;
  }

void update_delta_score_table(int dim, int n, int k, double *X, int *cluster_assignment_cur, double *cluster_centroid, int *cluster_member_count, double *point_move_score_table, int cc)
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
  
  
void  perform_move(int dim, int n, int k, double *X, int *cluster_assignment, double *cluster_centroid, int *cluster_member_count, int move_point, int move_target_cluster)
  {
    int cluster_old = cluster_assignment[move_point];
    int cluster_new = move_target_cluster;
  
   // update cluster assignment array
    cluster_assignment[move_point] = cluster_new;
    
   // update cluster count array
    cluster_member_count[cluster_old]--;
    cluster_member_count[cluster_new]++;
    
    if (cluster_member_count[cluster_old] <= 1)
      printf("WARNING: Can't handle single-member clusters! \n");
    
   // update centroid array
    for (int ii = 0; ii < dim; ii++)
      {
        cluster_centroid[cluster_old*dim + ii] -= (X[move_point*dim + ii] - cluster_centroid[cluster_old*dim + ii]) / cluster_member_count[cluster_old];
        cluster_centroid[cluster_new*dim + ii] += (X[move_point*dim + ii] - cluster_centroid[cluster_new*dim + ii]) / cluster_member_count[cluster_new];
      }
  }  
  
void cluster_diag(int dim, int n, int k, double *X, int *cluster_assignment_index, double *cluster_centroid)
  {
    int cluster_member_count[MAX_CLUSTERS];
    
    get_cluster_member_count(n, k, cluster_assignment_index, cluster_member_count);
     
    printf("  Final clusters \n");
    for (int ii = 0; ii < k; ii++) {
      printf("    cluster %d:     members: %8d, centroid (%.1f %.1f) \n", ii, cluster_member_count[ii], cluster_centroid[ii*dim + 0], cluster_centroid[ii*dim + 1]);
      // printf("    cluster %d:     members: %8d, centroid (%.1f %.1f %.1f) \n", ii, cluster_member_count[ii], cluster_centroid[ii*dim + 0], cluster_centroid[ii*dim + 1], cluster_centroid[ii*dim + 2]);

    }
  }

void copy_assignment_array(int n, int *src, int *tgt)
  {
    for (int ii = 0; ii < n; ii++)
      tgt[ii] = src[ii];
  }
  
int assignment_change_count(int n, int a[], int b[])
  {
    int change_count = 0;
    for (int ii = 0; ii < n; ii++) {
      int cond = (a[ii] != b[ii]);
      change_count = cond*(change_count+1) + (1-cond)*(change_count);
    }
  return change_count;
  }

void kmeans(
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
      fail("Error allocating dist arrays");
    
   // initial setup  
    calc_all_distances(dim, n, k, X, cluster_centroid, dist);
    choose_all_clusters_from_distances(dim, n, k, dist, cluster_assignment_cur);
    copy_assignment_array(n, cluster_assignment_cur, cluster_assignment_prev);

   // BATCH UPDATE
    double prev_totD = BIG_double;
    int batch_iteration = 0;
    while (batch_iteration < MAX_ITERATIONS) {
    // update cluster centroids
    calc_cluster_centroids(dim, n, k, X, cluster_assignment_cur, cluster_centroid);
    // see if we've failed to improve
    double totD = calc_total_distance(dim, n, k, X, cluster_centroid, cluster_assignment_cur);
    int cond = (totD > prev_totD);
    //  int *cluster_assignment_cur = (cluster_assignment_prev)*cond + (cluster_assignment_cur)*(1-cond);
    for (int i = 0; i < n; i++) {
      cluster_assignment_cur[i] = (cluster_assignment_prev[i])*cond + (cluster_assignment_cur[i])*(1-cond);
    }
    calc_cluster_centroids(dim, n, k, X, cluster_assignment_cur, cluster_centroid);
    // save previous step
    copy_assignment_array(n, cluster_assignment_cur, cluster_assignment_prev);
    
    // move all points to nearest cluster
    calc_all_distances(dim, n, k, X, cluster_centroid, dist);
    choose_all_clusters_from_distances(dim, n, k, dist, cluster_assignment_cur);
    
    prev_totD = totD;
    batch_iteration++;
}

cluster_diag(dim, n, k, X, cluster_assignment_cur, cluster_centroid);


   // ONLINE UPDATE
/* The online update prtion of this code has never worked properly, but batch update has been adequate for our projects so far.
    int online_iteration = 0;
    int last_point_moved = 0;
    
    int cluster_changed[MAX_CLUSTERS];
    for (int ii = 0; ii < k; ii++)
      cluster_changed[ii] = 1;
    
    int cluster_member_count[MAX_CLUSTERS];
    get_cluster_member_count(n, k, cluster_assignment_cur, cluster_member_count);
    
    while (online_iteration < MAX_ITERATIONS)
      {
//        printf("online iteration %d \n", online_iteration);

       // for each cluster
        for (int ii = 0; ii < k; ii++)
          if (cluster_changed[ii])
            update_delta_score_table(dim, n, k, X, cluster_assignment_cur, cluster_centroid, cluster_member_count, point_move_score, ii);
            
       // pick a point to move
       // look at points in sequence starting at one after previously moved point
        int make_move = 0;
        int point_to_move = -1;
        int target_cluster = -1;
        for (int ii = 0; ii < n; ii++)
          {
            int point_to_consider = (last_point_moved + 1 + ii) % n;
              
           // find the best target for it
            int best_target_cluster = -1;
            int best_match_count    = 0;
            double best_delta        = BIG_double;
            
           // for each possible target
            for (int jj = 0; jj < k; jj++)
              {
                double cur_delta = point_move_score[point_to_consider*k + jj];

               // is this the best move so far?
                if (cur_delta < best_delta)
                 // yes - record it
                  {
                    best_target_cluster = jj;
                    best_delta = cur_delta;
                    best_match_count = 1;
                  }
                else if (cur_delta == best_delta)
                 // no, but it's tied with the best one
                 best_match_count++;
              }

           // is the best cluster for this point its current cluster?
            if (best_target_cluster == cluster_assignment_cur[point_to_consider])
             // yes - don't move this point
               continue;

           // do we have a unique best move?
            if (best_match_count > 1)
             // no - don't move this point (ignore ties)
              continue;
            else
             // yes - we've found a good point to move
              {
                point_to_move = point_to_consider;
                target_cluster = best_target_cluster;
                make_move = 1;
                break;
              }
          }

        if (make_move)
          {
           // where should we move it to?            
            printf("  %10d: moved %d to %d \n", point_to_move, cluster_assignment_cur[point_to_move], target_cluster);

           // mark which clusters have been modified          
            for (int ii = 0; ii < k; ii++)
              cluster_changed[ii] = 0;
            cluster_changed[cluster_assignment_cur[point_to_move]] = 1;
            cluster_changed[target_cluster] = 1;

           // perform move
            perform_move(dim, n, k, X, cluster_assignment_cur, cluster_centroid, cluster_member_count, point_to_move, target_cluster);

           // count an iteration every time we've cycled through all the points
            if (point_to_move < last_point_moved)
              online_iteration++;

            last_point_moved = point_to_move;
          }

      }

*/
      
//    printf("iterations: %3d %3d \n", batch_iteration, online_iteration);
      
   // write to output array
    copy_assignment_array(n, cluster_assignment_cur, cluster_assignment_final);    
    
    free(dist);
    free(cluster_assignment_cur);
    free(cluster_assignment_prev);
    free(point_move_score);
  }  


int main(int argc, char const *argv[]) {
  // printf("kirat\n");
  // int dim = 2;
  // //double kirat_data[4] = {2.0, 2.0, 2.0, 2.0};
  // double kirat_data[2][2];
  // // kirat_data[0][0] = 2.0;
  // // kirat_data[0][1] = 1.0;
  // // kirat_data[1][0] = 2.0;
  // // kirat_data[1][1] = 1.0;
  // kirat_data[0][0] = 3.0;
  // kirat_data[0][1] = 5.0;
  // //kirat_data[0][2] = 7.0;
  // kirat_data[1][0] = 3.0;
  // kirat_data[1][1] = 5.0;
  // //kirat_data[1][2] = 7.0;
  // int n = 2;
  // int k = 1;
  // // double cluster_initial[1] = {20.0};
  // double cluster_initial[1][2];
  // cluster_initial[0][0] = 20.0;
  // cluster_initial[0][1] = 50.0;
  // //cluster_initial[0][2] = 520.0;

  // int cluster_final[1][2];

  printf("kirat\n");
  int dim = 3;
  // //double kirat_data[4] = {2.0, 2.0, 2.0, 2.0};
  // double kirat_data[2][2];
  // // kirat_data[0][0] = 2.0;
  // // kirat_data[0][1] = 1.0;
  // // kirat_data[1][0] = 2.0;
  // // kirat_data[1][1] = 1.0;
  // kirat_data[0][0] = 3.0;
  // kirat_data[0][1] = 5.0;
  // //kirat_data[0][2] = 7.0;
  // kirat_data[1][0] = 3.0;
  // kirat_data[1][1] = 5.0;
  // //kirat_data[1][2] = 7.0;
  int n = 100;
  int k = 3;
  // // double cluster_initial[1] = {20.0};
  // double cluster_initial[1][2];
  // cluster_initial[0][0] = 20.0;
  // cluster_initial[0][1] = 50.0;
  // //cluster_initial[0][2] = 520.0;

  // int cluster_final[1][2];

double kirat_data[n][dim] = {{0.3030697873146271,0.3030697873146271,0.3030697873146271},{0.2808936723034907,0.2808936723034907,0.2808936723034907},{0.30367809608796614,0.30367809608796614,0.30367809608796614},{0.3030199074031139,0.3030199074031139,0.3030199074031139},{0.31090633263350614,0.31090633263350614,0.31090633263350614},{0.3103354725841466,0.3103354725841466,0.3103354725841466},{0.2995354973029857,0.2995354973029857,0.2995354973029857},{0.28549467898513614,0.28549467898513614,0.28549467898513614},{0.3054152011984239,0.3054152011984239,0.3054152011984239},{0.3069385735651228,0.3069385735651228,0.3069385735651228},{0.29824512406138876,0.29824512406138876,0.29824512406138876},{0.30665682664420885,0.30665682664420885,0.30665682664420885},{0.2988424061307112,0.2988424061307112,0.2988424061307112},{0.2794963569295213,0.2794963569295213,0.2794963569295213},{0.2992941535538154,0.2992941535538154,0.2992941535538154},{0.286211787003142,0.286211787003142,0.286211787003142},{0.29074483572365967,0.29074483572365967,0.29074483572365967},{0.29327592413520487,0.29327592413520487,0.29327592413520487},{0.29636144567073214,0.29636144567073214,0.29636144567073214},{0.3012000270054786,0.3012000270054786,0.3012000270054786},{0.2880979854939783,0.2880979854939783,0.2880979854939783},{0.3137333451886978,0.3137333451886978,0.3137333451886978},{0.28811863018280026,0.28811863018280026,0.28811863018280026},{0.3048730309374213,0.3048730309374213,0.3048730309374213},{0.30512167668129586,0.30512167668129586,0.30512167668129586},{0.29617565574822113,0.29617565574822113,0.29617565574822113},{0.299647369535345,0.299647369535345,0.299647369535345},{0.31451993611543266,0.31451993611543266,0.31451993611543266},{0.2973065162953068,0.2973065162953068,0.2973065162953068},{0.2974672951598521,0.2974672951598521,0.2974672951598521},{0.6077049930996429,0.6077049930996429,0.6077049930996429},{0.5911618817816682,0.5911618817816682,0.5911618817816682},{0.5982867199332335,0.5982867199332335,0.5982867199332335},{0.605950938928775,0.605950938928775,0.605950938928775},{0.6165454308890274,0.6165454308890274,0.6165454308890274},{0.5937022166689185,0.5937022166689185,0.5937022166689185},{0.5990321836737337,0.5990321836737337,0.5990321836737337},{0.5871030592614939,0.5871030592614939,0.5871030592614939},{0.5930022282063667,0.5930022282063667,0.5930022282063667},{0.6130757252683101,0.6130757252683101,0.6130757252683101},{0.5978220475471928,0.5978220475471928,0.5978220475471928},{0.5872872348637117,0.5872872348637117,0.5872872348637117},{0.5880892314515322,0.5880892314515322,0.5880892314515322},{0.6070730159438522,0.6070730159438522,0.6070730159438522},{0.5894143782658511,0.5894143782658511,0.5894143782658511},{0.599005391327391,0.599005391327391,0.599005391327391},{0.6036133597799735,0.6036133597799735,0.6036133597799735},{0.6072065062391973,0.6072065062391973,0.6072065062391973},{0.5996041984673666,0.5996041984673666,0.5996041984673666},{0.6118012000166696,0.6118012000166696,0.6118012000166696},{0.5939191739484727,0.5939191739484727,0.5939191739484727},{0.5886750065063125,0.5886750065063125,0.5886750065063125},{0.5997426684771702,0.5997426684771702,0.5997426684771702},{0.6102334863401919,0.6102334863401919,0.6102334863401919},{0.5912972333278679,0.5912972333278679,0.5912972333278679},{0.6025604243740265,0.6025604243740265,0.6025604243740265},{0.6219972918131564,0.6219972918131564,0.6219972918131564},{0.5923896403159432,0.5923896403159432,0.5923896403159432},{0.6027579545288441,0.6027579545288441,0.6027579545288441},{0.5919086122601278,0.5919086122601278,0.5919086122601278},{0.5893599381995716,0.5893599381995716,0.5893599381995716},{0.5810214653023501,0.5810214653023501,0.5810214653023501},{0.589016806862104,0.589016806862104,0.589016806862104},{0.5911380139516503,0.5911380139516503,0.5911380139516503},{0.5970084355685829,0.5970084355685829,0.5970084355685829},{0.5993451823616759,0.5993451823616759,0.5993451823616759},{0.6033988664617769,0.6033988664617769,0.6033988664617769},{0.6096485616936191,0.6096485616936191,0.6096485616936191},{0.6025352417947997,0.6025352417947997,0.6025352417947997},{0.5897520322856289,0.5897520322856289,0.5897520322856289},{0.9081675950083055,0.9081675950083055,0.9081675950083055},{0.9167215466433015,0.9167215466433015,0.9167215466433015},{0.8922306368258723,0.8922306368258723,0.8922306368258723},{0.9163463050131526,0.9163463050131526,0.9163463050131526},{0.9042397040960038,0.9042397040960038,0.9042397040960038},{0.9049571448274706,0.9049571448274706,0.9049571448274706},{0.8981490887987427,0.8981490887987427,0.8981490887987427},{0.8860200663613924,0.8860200663613924,0.8860200663613924},{0.900912256877903,0.900912256877903,0.900912256877903},{0.8959109343915358,0.8959109343915358,0.8959109343915358},{0.8970430120772672,0.8970430120772672,0.8970430120772672},{0.9029120003866563,0.9029120003866563,0.9029120003866563},{0.9112702999606773,0.9112702999606773,0.9112702999606773},{0.8995570642703542,0.8995570642703542,0.8995570642703542},{0.900068574605907,0.900068574605907,0.900068574605907},{0.9033991377238719,0.9033991377238719,0.9033991377238719},{0.8888194555316604,0.8888194555316604,0.8888194555316604},{0.8999100358215115,0.8999100358215115,0.8999100358215115},{0.8740608415262292,0.8740608415262292,0.8740608415262292},{0.8976274545955861,0.8976274545955861,0.8976274545955861},{0.919480357139294,0.919480357139294,0.919480357139294},{0.9001299776113914,0.9001299776113914,0.9001299776113914},{0.9109115936626112,0.9109115936626112,0.9109115936626112},{0.9176965877955311,0.9176965877955311,0.9176965877955311},{0.8996853626211772,0.8996853626211772,0.8996853626211772},{0.9171306250899065,0.9171306250899065,0.9171306250899065},{0.8942957668659768,0.8942957668659768,0.8942957668659768},{0.90506280312969,0.90506280312969,0.90506280312969},{0.8988188251658166,0.8988188251658166,0.8988188251658166},{0.9130477624054308,0.9130477624054308,0.9130477624054308}};
  double cluster_initial[k][dim] = {{0.3, 0.3, 0.3}, {0.6, 0.6, 0.6}, {0.9, 0.9, 0.9}};

  int cluster_final[k][dim];
  kmeans(dim, (double*) kirat_data, n, k, (double*)cluster_initial, (int*) cluster_final);

  return 0;
}         
           



