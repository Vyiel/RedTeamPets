import hashlib
import sys
import psutil
import json
import graphviz


# shell_pid = int(input("Provide Shell PID "))

# print(Process(shell_pid).ppid())

print("""

This is a process tracer made in Python, that can be referenced for creating custom detection queries for various malwares.
Usage: 
Launch an Administrative CMD and note it's PID.
Launch this program as Administrator.
Provide the PID and Project name.
Run a sample malware via the original CMD.
Close the CMD.
This program will generate a JSON in Tree-Node structure, that can be visualized online and referenced for custom queries.
Sites:
https://jsoncrack.com/
https://vanya.jp.net/vtree/

Also, a graph is provided by default. For Displaying graph by default 'INSTALL GRAPHVIZ WINDOWS BINARY'

Bugs: Sometimes PSUTIL doesn't grab the network connections.

Made By ProfessorVeil

-----------------------------------------------------------------------------------------------------------

""")

pid = int(input("Administrative CMD PID: "))
proj_name = str(input("Activity Name: "))

proc_tree = {}
proc_pids = []
alreadytaken = []


def sha1(path):
    try:
        file_content = open(path, 'rb').read()
        hshlb = hashlib.sha1()
        hshlb.update(file_content)
        sha1 = hshlb.hexdigest()
        return sha1
    except:
        return None

def fetch_Network(Process_ID):
    conn_list = []
    PID = int(Process_ID)
    try:
        list_connections = psutil.Process(PID).connections(kind="all")
        # print(list_connections)

        for i in list_connections:
            try:
                Local_host = (i[3][0], i[3][1])
            except:
                Local_host = (None, None)

            try:
                Remote_host = (i[4][0], [4][1])
            except:
                Remote_host = (None, None)

            conn_list.append([Local_host, Remote_host])

    except:
        return None

    return conn_list


def get_children(pid):

    try:
        current_process = psutil.Process(pid)
        proc_pids.append(pid)

        cp_ppid = current_process.ppid()
        cp_name = current_process.name()
        cp_path = current_process.exe()
        cp_cli = current_process.cmdline()
        cp_hash = sha1(current_process.exe())
        cp_conn = fetch_Network(pid)
        cp_ppid_name = psutil.Process(cp_ppid).name()

        # print(cp_ppid, pid, cp_name, cp_cli, cp_hash)
        # print("---")


        if cp_ppid in proc_pids:
            if cp_ppid in proc_tree.keys():
                if pid not in alreadytaken:
                    proc_tree[cp_ppid].append([cp_ppid_name, pid, cp_name, cp_path, cp_cli, cp_hash, cp_conn])
                    alreadytaken.append(pid)
            else:
                proc_tree[cp_ppid] = [[cp_ppid_name, pid, cp_name, cp_path, cp_cli, cp_hash, cp_conn]]
                alreadytaken.append(pid)

        else:
            proc_tree[cp_ppid] = [[cp_ppid_name, pid, cp_name, cp_path, cp_cli, cp_hash, cp_conn]]
            alreadytaken.append(pid)

        # print(" | ")
        for i in current_process.children(recursive=True):
            get_children(i.pid)

    except psutil.NoSuchProcess:
        pass


# get_children(pid)

# --- ARRAY KEYS --- #
# Parent Name = 0
# PID = 1
# Name = 2
# Path = 3
# CLI = 4
# Hash = 5
# Conn = 6
# --- ARRAY KEYS --- #

while True:
    try:
        psutil.Process(pid).name()
        get_children(pid)
    except:
        break

# print(proc_tree)
unstructured_json = proc_tree

def tree_maker(parent_id):
    tree = {}
    if parent_id in unstructured_json:
        for child in unstructured_json[parent_id]:
            child_ID = child[1]
            child_name = child[2]
            child_path = child[3]
            child_cli = str(child[4])
            child_hash = child[5]
            child_conn = child[6]
            if child_ID in unstructured_json:
                tree[child_ID] = {"Name": child_name, "Path": child_path, "Command Line": child_cli, "Hash": child_hash, "Connections": child_conn, "Children": tree_maker(child_ID)}
            else:
                tree[child_ID] = {"Name": child_name, "Path": child_path, "Command Line": child_cli, "Hash": child_hash, "Connections": child_conn}
    return tree


first_item = list(unstructured_json)[0]
# print(first_item)

structured_tree = tree_maker(first_item)
structured_json = json.dumps(structured_tree, indent=4)
# print(json.dumps(b, indent=4))
file = open(proj_name+".json", 'w')
file.write(structured_json)
file.close()

graph_file = open(proj_name+'.json')
json_data = json.load(graph_file)


# This Graphviz part is suggested and initial code done by Chat GPT.#

def create_graph(json_data):
    graph = graphviz.Digraph()

    # Add nodes for the top-level process
    process_id = list(json_data.keys())[0]
    process_data = json_data[process_id]
    process_label = f" Name: {process_data['Name']} \n Path: {process_data['Path']} \n Hash: {process_data['Hash']} \n Command Line: {process_data['Command Line']} \n Connections: {process_data['Connections']}"
    process_label = process_label.replace("\\", "\\\\")
    graph.node(process_id, label=process_label, shape='box')

    # Recursively add nodes for child processes
    def add_children(process_id, children_data):
        for child_id, child_data in children_data.items():
            child_label = f" Name: {child_data['Name']} \n Path: {child_data['Path']} \n Hash: {child_data['Hash']} \n Command Line: {child_data['Command Line']} \n Connections: {child_data['Connections']}"
            child_label = child_label.replace("\\", "\\\\")
            graph.node(child_id, label=child_label, shape='box')
            graph.edge(process_id, child_id)
            if 'Children' in child_data:
                add_children(child_id, child_data['Children'])

    if 'Children' in process_data:
        add_children(process_id, process_data['Children'])

    graph.attr(rankdir='LR')  # Left to right layout
    graph.attr(fontname='Helvetica')

    return graph


graph = create_graph(json_data)
graph.render(proj_name, format="pdf", view=True)

print("A JSON file is stored with the project name. Go to JSONCrack.com and Visualize.")
print("Enter Any key to Exit!!! ")
input()
sys.exit()
