import engine
from tkinter import Tk, Label, Button, Frame, StringVar, OptionMenu, N, W, S, E, Entry, END
from library import LIBRARY

class GenevaGUI:
    def __init__(self, root):
        
        root.title("Geneva")
        self.master = root


        # Define port

        self.port = Entry(root)
        self.port.insert(END, "Port")
        self.port.grid(row=0, column=0)

        # Define start and stop buttons
        self.button = Button(root, text="Start Running Strategy", command = self.start)
        self.button.grid(row=3, column=1)


        # Define Dropdown menu
        maxStrategyNum = len(LIBRARY)
        choices = [x for x in range(maxStrategyNum)]
        mainframe = Frame(root)
        mainframe.grid(row=0, column=2, sticky=(N,W,E,S))
        mainframe.columnconfigure(0, weight = 1)
        mainframe.rowconfigure(0, weight = 1)
        #mainframe.pack(pady = 100, padx = 100)

        self.strategy_menu = StringVar(root)
        self.strategy_menu.set(0)
        self.strategy = self.strategy_menu.get()

        popupMenu = OptionMenu(mainframe, self.strategy_menu, *choices)
        Label(mainframe, text="Strategy index").grid(row = 1, column = 2)
        popupMenu.grid(row = 0, column = 2)
        
        self.strategy_menu.trace('w', self.select_strategy)

    def start(self):
        try:
            self.eng = engine.Engine(self.port.get(), LIBRARY[int(self.strategy_menu.get())][0], log_level="debug")
            self.eng.initialize()
            self.button = Button(self.master, text="Stop Running Strategy", command=self.stop)
            self.button.grid(row=3, column=1)
        except:
            print("Initialization failed.")
        
    def stop(self):
        if self.eng:
            self.eng.shutdown()
        self.button = Button(self.master, text="Start Running Strategy", command = self.start)
        self.button.grid(row=3, column=1)

    def select_strategy(self, *args):
        pass
    
def main():
    root = Tk()
    GenevaGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()