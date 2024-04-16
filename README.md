# ROSpace Dataset 

This repository includes all the code used for the paper: 

**Intrusion Detection Dataset for a ROS2-Based Cyber-Physical System** ([link to preprint](https://arxiv.org/abs/2402.08468)).

The dataset can be dowloaded from [link to dataset](https://figshare.com/s/7937b17067d20f57fee4).

In each folder, you'll find the code necessary to replicate the steps of the experimental campaign.

In particular, **5_usage_note** folder contains the notebook and the instructions for training and testing an Intrusion Detector based on machine learning using the ROSpace dataset.

## System and Dataset description
ROSPaCe is a dataset for intrusion detection composed by performing penetration testing on SPaCe, an embedded cyber-physical system built over Robot Operating System 2 (ROS2). Features are monitored from three architectural layers: the Linux operating system, the network, and the ROS2 services.
We perform attacks through the execution of discovery and DoS attacks, for a total of 6 attacks, with 3 of them specific to ROS2. We collect data from the network interfaces, the operative system, and ROS2, and we merge the observations in a unique dataset using the timestamp.
The final version of ROSPaCe includes 30 247 050 data points and 482 columns excluding the label. The features are 25 from the the Linux operating system, 5 from the ROS2 services, and 422 from the network. The dataset is encoded in the complete_dataset.csv 
file for a total of 40.5 GB. The dataset contains about 23 million attack data points and above 6.5 million normal data points (78% attacks, 22% normal). We provide a lightweight version of the ROSpace dataset by selecting the best-performing 60 features. This includes the 30 features from the Linux operating system, the ROS2 services, and the 30 best-performing features from the network.

![image](https://github.com/TommasoPuccetti/rospace_dataset/assets/103670615/7ed3c3b2-e1c2-4e89-9ee5-cb71b3132b6a)


## Files in the repository
In particular:

* **0_attack**: includes the code used to launch the selected attacks on the SPaCe System.
    - **`attack.py`**: launch the attacks included in the experimental campaign.

* **1_processing**: includes the code used to convert the raw data collected during the monitoring campaign and to merge the processed data from different monitors into a unified dataset.   
    - **`custom_pcapng2csv.py`**: this script converts the network traffic collected by Tshark and stored in .pcapng files into csv files. The script can be launched to  (-files argument) or to  (-d argument).
  ```
  ARGUMENTS
  -files: convert a single file.
  -d: convert each files inside a specified folder. Performed in parallel by instantiating multiple sub processes.
  ```
  ```    
  Examples:
      python custom_pcapng2csv.py -files /folder/file.pcapng.
      python custom_pcapng2csv.py -d /folder/folder_where_pcapng_files_are_stored.
  ```
    - **`csv_merging_parallel.py`**: this script merges csv files from the 3 different monitors as described in the "Data Processing and Labeling" section of the paper.
```
ARGUMENTS:
    -s: the path to the csv file containing system indicators (Os Monitor output in csv)
    -n: the path(s) to the csv file(s) containing network packets information (thsark processed output in csv)
    -r: the path to the csv file containing ROS2 indicators (ROS Monitor Node output in csv)
    -a: the path to the csv file containing attacks logs (attack.py script output)
    -p: switch on or off multithreading or multiprocessing. Accepted values are:
    -t, thread, threads for multithreading:
        -p, proc, process for multiprocessing; 
        -s, seq, sequential, none, not, no, off for disabling it (default).
```
     
* **2_labeling**: includes the code used to label the merged dataset.
  - **`labeling.py`**: labels the merged dataset using the timestamp included in the attack.py output log. This log indicates the time intervals in which the attacker is performing attacks or the system is running normally.
```
ARGUMENTS:
    -s: the path to the csv file containing the unlabeled csv.        
    -a: the path to the csv file containing attacks information (attack.py script output log)
```

* **3_complete_dataset**: includes the code used to compose the final complete_dataset.csv file (ADD LINK).
  - **`complete_dataset_composition.ipypng`**: This notebook reports the code used to process the complete ROSPace dataset obtained after merging and labeling operations, namely:
    - delete duplicated/unusefull columns/features 
    - delete columns with 1 or 0 unique values
  - **`final_merging.ipypng`**: in this notebook we report the code used to merge different batches of the final dataset on the columns, using their common features. This way we keep only the features that are more general (they are in common between all the csv files that compose the final dataset).
     
* **4_reduced_dataset**: we composea reduced version of the dataset designed to retain essential features while discarding less critical ones. This way we reduce the computational resources required for analysis.
  - **`reduced_dataset_composition.ipypng`**: in this notebook we report the code used to compose the reduced version of the dataset.
     
* **5_usage_notes**:
  - **`usage_note_A_detection_shuffled.ipypng`**: Describe how to use the dataset for Intrusion Detection. Our focus is to distinguish between normal and attack data points: therefore, we drop all the time and sequence-related features, and we shuffle the dataset. Steps are: 
    1.  Drop all columns containing timestamps or that may contain information on data sequences.
    2.  Shuffle the dataset.
    3.  Divide the dataset into train and test sets by applying a 60/40 split. 
    4.  Train and test a binary classifier, compute the appropriate metrics (see the Technical Validation below), and visualize results.
  - **`usage_note_B_detection_time_series.ipypng`**: In this scenario, we shift our focus to investigate how long an attacker is undetected. The notion of time, in this case, is central: we want to train the ML detector to make decisions based on system evolution through time rather than deciding on individual data points.
    steps needed are the following:
    1.  Identify all the pairs (normal sequence, attack sequence) in the dataset. We call each of these pairs a block.
    2.  60% of randomly selected blocks are assigned to the train set, and the remaining 40% to the test set. This way we train the ML detector with blocks of ordered data points, each block containing approximately 30 seconds of normal data, that are followed by a variable amount of attack data.
    3.  Train and test a binary classifier, compute the appropriate metrics (see the Technical Validation below), and visualize results.
   
