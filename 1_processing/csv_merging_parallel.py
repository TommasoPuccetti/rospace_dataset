#!/usr/bin/env python

import argparse, os
# import modin.pandas as pd
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import timedelta
from datetime import datetime as dt
import glob
import gc
import concurrent.futures as fut
from concurrent.futures import Future
from concurrent.futures import ThreadPoolExecutor
import traceback


parser = argparse.ArgumentParser(description="Helper script to merge csv files "
					"from different monitor for SPaCe dataset creation")

parser.add_argument('-s', '--system', metavar='PATH', type=str,
                    help='the path to the csv file containing system indicators (Madness output)',
                    nargs=1, required=True)

parser.add_argument('-n', '--network', metavar='PATHS', type=str,
                    help='the path(s) to the csv file(s) containing network packets information (thsark processed output)',
                    nargs='+', required=True)

parser.add_argument('-r', '--ros', metavar='PATH', type=str,
                    help='the path to the csv file containing ROS2 indicators (MonitorNode output)',
                    nargs=1, required=True)

parser.add_argument('-a', '--attacks', metavar='PATH', type=str,
                    help='the path to the csv file containing attacks information (attack.py script output)',
                    nargs=1, required=True)

parser.add_argument('-p', '--parallelize', metavar='TYPE',
                    help='switch on or off multithreading or multiprocessing. '
					'Accepted values are: t, thread, threads for multithreading; '
					'p, proc, process for multiprocessing; '
					's, seq, sequential, none, not, no, off for disabling it (default)',
                    required=False, default=None)


args = parser.parse_args()

parallelize = True
if args.parallelize in ['t', 'thread', 'threads']:
	import concurrent.futures as fut
	from concurrent.futures import ThreadPoolExecutor as Executor
	from concurrent.futures import Future
elif args.parallelize in ['p', 'proc', 'process']:
	import concurrent.futures as fut
	from concurrent.futures import ProcessPoolExecutor as Executor
	from concurrent.futures import Future
elif args.parallelize is None or args.parallelize in ['s', 'seq', 'sequential', 'not', 'no', 'off', 'none']:
	parallelize = False
else:
	parser.error(f'unrecognized parallelization strategy "{args.parallelize}"')

def load_and_preprocess(path, timestamp_col_name, time_unit='ms', columns=None, nrows=None, skiprows=None):
	try:

		if "attack" in str(path): 
			time_unit = "s"

		print(f"Loading '{path}'...", end='', flush=True)
		content = pd.read_csv(path, nrows=nrows, skiprows=skiprows)

		if "packets" in str(path):
			time_unit = "s"
			#content[timestamp_col_name] = content[timestamp_col_name].apply(lambda x: x*1000)

		if columns is not None:
			content.columns = columns
		print(f'{path} loaded')
		path = str(path)
		## non capisco perché non siano già ordinati...
		print(f"Sorting {path}...", end='', flush=True)
		# content = content.sort_values(timestamp_col_name)
		content.sort_values(timestamp_col_name, inplace=True)
		gc.collect()
		print(f'{path} sorted')
		print(f"Convert timestamp on {path}...", end='', flush=True)
		timestamp = content[timestamp_col_name]
		#content = content.drop(columns=[timestamp_col_name])
		content.drop(columns=[timestamp_col_name], inplace=True)
		
		#content = content.assign(timestamp=pd.to_datetime(timestamp, unit=time_unit))
		content = content.assign(timestamp=pd.to_datetime(timestamp, unit=time_unit), inplace=True)
		del timestamp
		gc.collect()
		print(f'{path} converted')
		min_stamp = content['timestamp'].min()
		max_stamp = content['timestamp'].max()
	except Exception as e:
		# print(f"in {path}: {str(e)}", level='Error')
		_print(e, type(e))
		raise Exception(f"processing {path}: {str(e)}")
	return content, min_stamp, max_stamp

def process_batch(args_list):
	try:
		with ThreadPoolExecutor() as executor:
			fut_list.append(executor.submit(load_and_preprocess, *args_list.pop()))
			fut_list.append(executor.submit(load_and_preprocess, *args_list.pop()))
			fut_list.append(executor.submit(load_and_preprocess, *args_list.pop()))
			attacks_f = executor.submit(load_and_preprocess, *args_list.pop())
			fut.wait([*fut_list, attacks_f])
			
	except Exception as e:
		# print(f"in {path}: {str(e)}", level='Error')
		_print(e, type(e))
		raise Exception(f"processing {path}: {str(e)}")

with open('csv_manipulation.log', 'w+') as log_file:
	_print=print

	def print(message='', level='Info', **kwargs):
		now = dt.now()
		_print(message, **kwargs)
		log_file.write(f"{now.strftime('%a %b %d %H:%M:%S 2023')}  [{level}]\t{message}\n")


	try:
		system_p = Path(args.system[0]).resolve()
		network_p = [Path(net).resolve() for net in args.network]
		ros2_p = Path(args.ros[0]).resolve()
		attacks_p = Path(args.attacks[0]).resolve()
		net_str = '\n\t'.join(args.network)

		if args.parallelize in ['p', 'proc', 'process']:
			from concurrent.futures import ProcessPoolExecutor as Executor

			with Executor() as executor:
				arguments = []
				for i in range(executor._max_workers):
					pass
			

		if parallelize:
			with Executor() as executor:
				fut_list = [executor.submit(load_and_preprocess, net_p, 'layers.frame.frame.time_epoch') for net_p in network_p]
				system_f = executor.submit(load_and_preprocess, system_p, 'ms', 'ms')
				ros2_f = executor.submit(load_and_preprocess, ros2_p, 'ms', 'ms')
				attacks_f = executor.submit(load_and_preprocess, attacks_p, 'timestamp')
				
				#fut.wait([system_f, ros2_f, attacks_f])
				attacks, stamp_limit, _ = attacks_f.result()
				#merged = pd.DataFrame([], columns=['timestamp'])
				for future in fut.as_completed(fut_list):
					content, stamp, _ = future.result()
					# stamp_min = min(stamp_min, stamp)
					stamp_limit = max(stamp, stamp_limit)
					merged = merged[(merged['timestamp'] >= stamp_limit)]
					content = content[(content['timestamp'] >= stamp_limit)]
					merged = pd.merge_asof(merged, content, on='timestamp', 
						tolerance=timedelta(milliseconds=100), direction='nearest')
					gc.collect()

				system, s_min = system_f.result()
				ros2, r_min = ros2_f.result()
				attacks, a_min = attacks_f.result()
				network = []
				n_min = pd.to_datetime('2100-01-01')
				for net_f in network_f:
					net, stamp = net_f.result()
					n_min = min(n_min, stamp)
					network.append(net)
		else:
			system, s_min, s_max = load_and_preprocess(system_p, 'ms', 'ms')
			print(system)
			network = []
			n_min = pd.to_datetime('2100-01-01')
			n_max = pd.to_datetime('1900-01-01')
			attacks, a_min, a_max = load_and_preprocess(attacks_p, 'timestamp')
			for net_p in network_p:
				net, stamp_min, stamp_max = load_and_preprocess(net_p, 'layers.frame.frame.time_epoch')
				n_min = min(n_min, stamp_min)
				n_max = max(n_max, stamp_max)
				network.append(net)
			ros2, r_min, r_max = load_and_preprocess(ros2_p, 'ms', 'ms')
		t_min = max(s_min, n_min, r_min, a_min)
		t_max = min(s_max, n_max, r_max, a_max)
		# t_min = max(s_min, n_min, r_min)

		print(system)
		print(attacks)
		print(ros2)
		print(network)

		print()
		print(f"system: {system['timestamp'][1]}")
		print(f"network: {network[0]['timestamp'][1]}")
		print(f"ros2: {ros2['timestamp'][1]}")
		print(f"attacks: {attacks['timestamp'][1]}")
		print(f'Chosen timestamp lower limit = {t_min}')
		#print(f"system: {system['timestamp'][-1]}")
		#print(f"network: {network[0]['timestamp'][-1]}")
		#print(f"ros2: {ros2['timestamp'][-1]}")
		#print(f"attacks: {attacks['timestamp'][-1]}")
		print(f'Chosen timestamp upper limit = {t_max}')
		print()

		# system = system[(system['timestamp']>= t_min)]
		# network = [net[(net['timestamp']>= t_min)] for net in network]
		# ros2 = ros2[(ros2['timestamp']>= t_min)]
		# attacks = attacks[(attacks['timestamp']>= t_min)]
		system.drop(system[(system['timestamp'] < t_min)].index, inplace=True)
		for net in network:
			net.drop(net[(net['timestamp'] < t_min)].index, inplace=True)
		ros2.drop(ros2[(ros2['timestamp']< t_min)].index, inplace=True)

		attacks.drop(attacks[(attacks['timestamp']< t_min)].index, inplace=True)

		# system = system[(system['timestamp'] <= t_max)]
		# network = [net[(net['timestamp'] <= t_max)] for net in network]
		# ros2 = ros2[(ros2['timestamp'] <= t_max)]
		# attacks = attacks[(attacks['timestamp'] <= t_max)]
		system.drop(system[(system['timestamp'] >= t_max)].index, inplace=True)

		for net in network:
			net.drop(net[(net['timestamp'] >= t_max)].index, inplace=True)
		ros2.drop(ros2[(ros2['timestamp'] >= t_max)].index, inplace=True)
		print(attacks)
		attacks.drop(attacks[(attacks['timestamp'] >= t_max)].index, inplace=True)

		# system = system.drop(columns=['datetime'])
		# ros2 = ros2.drop(columns=['datetime'])
		#system.drop(columns=['datetime'], inplace=True)
		#ros2.drop(columns=['datetime'], inplace=True)
		# attacks = attacks.drop(columns=['date'])
		gc.collect()

		print('Lenghts')
		print(f"system: {len(system)}")
		net_str = '\n\t'.join(str(len(net)) for net in network)
		print(f"network: {net_str}")
		print(f"ros2: {len(ros2)}")
		print(f"attacks: {len(attacks)}")
		print()

		print("Preparing to merge")
		merged = network[0]
		if len(network) > 1:
			print('Pre-merge, all network...', end='', flush=True)
			for i in range(1..len(network)):
				merged = pd.merge(merged, network[i])
			print('done')
		del network
		print('First merge...', end='', flush=True)
		merged = pd.merge_asof(merged, system, on='timestamp', tolerance=timedelta(milliseconds=100),
			direction='nearest')
		print('done')
		del system
		gc.collect()
		print('Second merge...', end='', flush=True)
		merged = pd.merge_asof(merged, ros2, on='timestamp', tolerance=timedelta(milliseconds=100),
			direction='nearest')
		print('done')
		del ros2
		gc.collect()
		# merged = pd.merge_asof(merged, ros2, on='ms', tolerance=timedelta(milliseconds=100),
		# 	direction='nearest')

		print('Delete duplicate column "timestamp"...', end='', flush=True)
		stamp_col = merged['timestamp']
		# merged = merged.drop(columns=['timestamp'])
		merged.drop(columns=['timestamp'], inplace=True)
		merged.insert(loc=2,column='timestamp',value=stamp_col)
		# merged = merged.drop(merged.columns[[0,1]], axis=1) # questo non mi ricordo cosa fa...
		merged.drop(merged.columns[[0,1]], axis=1, inplace=True) # questo non mi ricordo cosa fa...
		gc.collect()
		print('done')

		working_dir = Path(os.getcwd()).resolve()
		target_dir = working_dir / 'merged-dataset'
		if not target_dir.exists():
			target_dir.mkdir()
		target = target_dir / f'merged-{dt.now().strftime("%d_%m_%Y@%H_%M_%S")}_unlabelled.csv'
		print(f'Saving to {target}...', end='', flush=True)
		merged.to_csv(target)
		print('done')
		
		print('Labeling attacks...', end='', flush=True)
		to_label = []
		for index, row in merged.iterrows():
			current = attacks[(attacks['timestamp'] <= row['timestamp'])].iloc[-1]
			label = current['event']
			attack = current['attack']
			succ = attacks[(attacks['timestamp'] > row['timestamp'])]
			if len(succ) <= 0:
				# discard values that are after the end of the attack
				to_label.append(None)
				continue
			next_label = succ.iloc[0]['event']
			if label == 'start':
				to_label.append(attack)
			elif label == 'end' and next_label == 'observe':
				# observations between the end of an attack and the beginning of an observe period. These observations are discarded. 
				to_label.append('discard')
			elif label == 'observe' and next_label == 'start':
				to_label.append(label)
			else:
				print(f'unexpected entry (timestamp={row["timestamp"]} at index {index}) between {label} and {next_label} found: flagged to be removed', level='Warning')
				to_label.append('discard')

		label_values = np.array(to_label)
		del to_label
		# merged = merged.assign(attack=lambda x: (x.index == to_label).astype(int))
		# merged = merged.assign(attack=label_values)
		merged = merged.assign(attack=label_values, inplace=True)
		gc.collect()
		print(merged['attack'])

		print('Removing observations outside boundaries...')
		print(merged.shape)
		print(merged)
		merged = merged[(merged['attack'] != 'discard')]
		print(merged)
		gc.collect()
		print('done')

		working_dir = Path(os.getcwd()).resolve()
		target_dir = working_dir / 'merged-dataset'
		if not target_dir.exists():
			target_dir.mkdir()
		target = target_dir / f'merged-{dt.now().strftime("%d_%m_%Y@%H_%M_%S")}.csv'
		print(f'Saving to {target}...', end='', flush=True)
		merged.to_csv(target)
		print('done')

	except Exception as e:
		_print(str(e), type(e))
		print(str(e), level='Error')
		traceback.print_exc()
	# del(system)
	# del(network)
	# del(ros2)
	# del(merged)
	# gc.collect()
