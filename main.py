import generatekey
import encrypt
import decrypt
import gui

if __name__ == "__main__":
    import tkinter as tk
    
    root = tk.Tk()
    app = gui.AESApp(root)
    root.mainloop()
