from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
import logging
import sys
import hashlib
import yaml
import sqlite3
import time
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, format='%(message)s', level=logging.WARN)


with open("config.yml","r") as konfiguration:
    config : dict = yaml.safe_load(konfiguration)
    logger.info("Opening config file")

with sqlite3.connect("data.db") as data:
    cursor = data.cursor()
    query = """
        CREATE TABLE IF NOT EXISTS List_file (
        file_name TEXT PRIMARY KEY,
        file_size INTERGER,
        file_hash TEXT,
        modified TIMESTAMP,
        access TIMESTAMP)
        """
    cursor.execute(query)
    data.commit()


def hasher(data):
    try:
        with open(data, "rb") as file:
            shas = hashlib.file_digest(file, "sha256")
            return shas.hexdigest()
    except FileNotFoundError:
        pass
def get_all_files(): #formerly known as base_line_scan()
    EXCLUDE_DIRS = {".cache", ".git", "node_modules", ".venv", "__pycache__","cache",}
    for z in config["file"]:
        root = Path(z)
        for i in root.rglob("*"):
            if i.is_dir():
                pass
            elif i.is_file() and not any(part in EXCLUDE_DIRS for part in i.parts):
                yield i

    print("operation complete")

create_table_query = '''
CREATE TABLE IF NOT EXISTS List_file (
        file_name TEXT PRIMARY KEY,
        file_size INTERGER,
        file_hash TEXT,
        modified TIMESTAMP,
        access TIMESTAMP
    )    
    '''

def base_scan():
    with sqlite3.connect("data.db") as data:
        cursor = data.cursor()
        cursor.execute(create_table_query)
        data.commit()
    records = []
    for file in get_all_files():
        print(f"scanning:{file}")
        hashed = hasher(file)
        time = datetime.fromtimestamp(file.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        time_access = datetime.fromtimestamp(file.stat().st_atime).strftime("%Y-%m-%d %H:%M:%S")
        records.append((str(file),file.stat().st_size, hashed, time, time_access))
    with sqlite3.connect("data.db") as data:
        cursor = data.cursor()
        insert_query = '''
        INSERT OR REPLACE INTO List_file(file_name,file_size, file_hash, modified, access)
        VALUES(?,?,?,?,?)
        '''
        cursor.executemany(insert_query, records)


def checker():
    with sqlite3.connect("data.db") as conn:
        ret_query = """
            SELECT file_hash,file_size,modified, access
            FROM List_file
            WHERE File_name = CAST(? AS TEXT)
            """
        cursor = conn.cursor()
        for file in get_all_files():
            fiile = Path(file)
            cursor.execute(ret_query, [str(file)]) #
            tada = cursor.fetchall()
            time = datetime.fromtimestamp(fiile.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            time_accsess = datetime.fromtimestamp(fiile.stat().st_atime).strftime("%Y-%m-%d %H:%M:%S")
     #in this block of code check if this file already registered within db, need to learn sqlite
            for i in tada:
                if fiile.stat().st_size != i[1]:
                    if hasher(file) != i[0]:
                        print(f"this {file} is sus")
                elif time != i[2]:
                    print(f"{file} has been modified")
                    logger.info(f"{file} modified at {time}")
                elif time_accsess != i[3]:
                    print(f"{file} base been accessed at {time_accsess}")

                else:
                    continue
            conn.commit()


    #and this block is used to notify admin if theres a diffrence in data, this block may not be used 

def peeker(file):
    datp = Path(file)
    query = f"""
        SELECT file_hash, file_size, modified
        FROM List_file
        where file_name = CAST(? AS TEXT)
        """
    with sqlite3.connect("data.db") as data:
        try:
            cursor = data.cursor()
            cursor.execute(query, [str(file)])
            feedback = cursor.fetchone()
            time = datetime.fromtimestamp(datp.stat().st_mtime)
            time_pretty=time.strftime("%Y-%m-%d %H:%M:%S")
            if feedback == None:
                logger.warning(f"{file} is unregistered file, be wary")
            else:
                if datp.stat().st_size != feedback[1] or time_pretty != feedback[2]:
                    if hasher(file) != feedback[0]:
                        logger.warning(f"{file} has been tampered and need to be analyzed")
                    else:
                        logger.warning(f"{file} has been modified or accessed")
        except FileNotFoundError:
            logger.warning(f"cannot found file: {file}")
            
def time_checker():
    last_scan = config["time"]
    last_scan_time = datetime.strftime(last_scan,"%Y-%m-%d %H:%M:%S")
    time_now = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")
    delta_time = time_now- last_scan_time
    if delta_time.total_seconds() >= 86400:
        with open("config.yml", "w") as mark:
            config["time"] = str(datetime.now())
            yaml.dump(config,mark,default_flow_style=False, sort_keys=False)
            return True


class Watcher_File(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.counter = {}
    def on_closed(self, event):
        if not event.is_directory:
            counter=self.counter
            if counter.get(event.src_path) == None:
                counter[event.src_path] = 0
            
            elif counter.get(event.src_path) == 0:
                peeker(event.src_path)
                counter[event.src_path] += 1
            else:
                counter[event.src_path] = counter.get(event.src_path)+1
    def on_created(self, event):
        if not event.is_directory:
            counter = self.counter
            if counter.get(event.src_path) == None:
                counter[event.src_path] = 0
            elif counter.get(event.src_path) == 0:
                logger.warning(f"ooh a new file {event.src_path}")
                peeker(event.src_path)
            else:
                pass
    #on deletd function are still in development
    def on_deleted(self, event):
        if event.is_directory:
            logger.warning(f"warning {event.src_path} is deleted")
        if not event.is_directory:
            pass






if __name__ == "__main__":
    try:
        with sqlite3.connect("data.db") as butch:
            cursor = butch.cursor()
            m =cursor.execute("SELECT 1 FROM List_file LIMIT 1;")
            if cursor.fetchone() == None:
                print("running base scan") #using print because to see in terminal
                base_scan()
            else:
                pass
            butch.commit()
    except KeyboardInterrupt:
        print(f"\n bro what the fuck")

    try:
        event_handler = Watcher_File()
        observer = Observer()
        for i in config["file"]:
            observer.schedule(event_handler, i, recursive=True)
            observer.start()

        while True:
            time.sleep(900)
            logger.info("running daily checking") #using print with the same reason
            checker()
        #the commented code are still in repair, this one have have formatting problem

    except KeyboardInterrupt:
        observer.stop()
        print("\n bro what the fuck")
