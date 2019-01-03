from google.cloud import bigquery
import sqlite3
import pickle
import sys
import time


def query(from_time, to_time):
    global client, con, cur
    q_data = (
        f'SELECT * FROM `bigquery-public-data.ethereum_blockchain.traces` '
        f'WHERE block_timestamp >= "{from_time}" AND block_timestamp < "{to_time}" AND from_address is not null'
    )

    query_job = client.query(q_data).result()
    # f = open(f'/Users/Still/Desktop/w/db/{from_time}-{to_time}.txs','wb')
    # pickle.dump(query_job,f)
    # f.close()
    print(f'inserting into database...')
    count = 0
    for row in query_job:
        # import IPython;IPython.embed()
        try:
            cur.execute(f'''insert into traces (transaction_hash,transaction_index,from_address,to_address,value,input,output,trace_type,call_type,reward_type,gas,gas_used,subtraces,trace_address,error,status,block_timestamp,block_number,block_hash) values(
                "{row[0]}", "{row[1]}", "{row[2]}", "{row[3]}", "{float(row[4])}", "{row[5]}", "{row[6]}", "{row[7]}", "{row[8]}",
                "{row[9]}", "{row[10]}", "{row[11]}", "{row[12]}", "{row[13]}", "{row[14]}", "{row[15]}", "{row[16].strftime("%Y-%m-%d %H:%M:%S")}", {row[17]}, "{row[18]}"
                )''')
        except sqlite3.Error as e:
            print(e)
            import IPython
            IPython.embed()
        count += 1
        sys.stdout.write(str(count) + '\r')
        sys.stdout.flush()

    print(f'{count} inserted')
    return count


def back1Hour(time):
    if time[11:13] != '00':
        if int(time[11:13]) < 11:
            return time[:11] + '0' + f'{int(time[11:13])-1}' + ':00:00'
        else:
            return time[:11] + f'{int(time[11:13])-1}' + ':00:00'
    else:
        if int(time[8:10]) < 11:
            return time[:8] + '0' + f'{int(time[8:10])-1}' + ' 23:00:00'
        else:
            return time[:8] + f'{int(time[8:10])-1}' + ' 23:00:00'


client = bigquery.Client()
con = sqlite3.connect('/home/jay/w/db/big_query.db')
cur = con.cursor()

from_time = '2018-11-24 01:00:00'
to_time = '2018-11-24 02:00:00'
while True:
    print(f'querying block from {from_time} to {to_time}...')
    count = query(from_time, to_time)
    cur.execute(
        f"insert into timestamp_txs(from_time,to_time,txs_number) values ('{from_time}','{to_time}',{count})")
    con.commit()
    print(f'complete, {time.ctime()}')
    to_time = from_time
    from_time = back1Hour(from_time)


con.close()
