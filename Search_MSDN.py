############################################################################################
##
## IDA plugin template code shamelessly stolen from @herrcore's GitHub (with permission)
## https://github.com/OALabs/hexcopy-ida/blob/main/hexcopy.py
##
## One-Click MSDN search!
##
## Updated for IDA 7.xx and Python 3
##
## To install:
##      Copy script into plugins directory, i.e: C:\Program Files\<ida version>\plugins
##      Install BeautifulSoup (bs4) and requests for whichever version of Python3 you are running
##
## To run:
##      Highlight Windows API function and right click and select "Search MSDN"
##      The link to the MSDN page for that function will open in a new browser window!
##
############################################################################################


__AUTHOR__ = 'SplishSplash'

PLUGIN_NAME = "Search_MSDN"
PLUGIN_HOTKEY = 'Ctrl+M'
VERSION = '1.0'

import sys
import ida_kernwin
import idc
import idaapi
import idautils
from bs4 import BeautifulSoup
import webbrowser
import requests
import re

major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)
using_pyqt5 = using_ida7api or (major == 6 and minor >= 9)

if using_pyqt5:
    import PyQt5.QtGui as QtGui
    import PyQt5.QtCore as QtCore
    import PyQt5.QtWidgets as QtWidgets
    from PyQt5.Qt import QApplication

else:
    import PySide.QtGui as QtGui
    import PySide.QtCore as QtCore

    QtWidgets = QtGui
    QtCore.pyqtSignal = QtCore.Signal
    QtCore.pyqtSlot = QtCore.Slot
    from PySide.QtGui import QApplication


def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return search_init()


class search_init(idaapi.plugin_t):
    """
    The IDA Plugin for Search_MSDN.
    """

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Search MSDN"
    help = "Highlight Windows API and right-click 'Search MSDN'"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    # --------------------------------------------------------------------------
    # Plugin Overloads
    # --------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        # initialize the menu actions our plugin will inject
        self._init_action_search()

        # initialize plugin hooks
        self._init_hooks()

        # done
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """

        # unhook our plugin hooks
        self._hooks.unhook()

        # unregister our actions & free their resources
        self._del_action_search()

        # done
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    # --------------------------------------------------------------------------
    # Plugin Hooks
    # --------------------------------------------------------------------------

    def _init_hooks(self):
        """
        Install plugin hooks into IDA.
        """
        self._hooks = Hooks()
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()

    def _init_hexrays_hooks(self):
        """
        Install Hex-Rrays hooks (when available).
        NOTE: This is called when the ui_ready_to_run event fires.
        """
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)

    # --------------------------------------------------------------------------
    # IDA Actions
    # --------------------------------------------------------------------------

    SEARCH = "prefix:Search_MSDN"

    def _init_action_search(self):
        """
        Register the copy bytes action with IDA.
        """
        if (sys.version_info > (3, 0)):
            # Describe the action using python3 copy
            action_desc = idaapi.action_desc_t(
                self.SEARCH,  # The action name.
                "Search MSDN",  # The action text.
                IDACtxEntry(search_web),  # The action handler.
                PLUGIN_HOTKEY,  # Optional: action shortcut
                "Search MSDN for Windows API",  # Optional: tooltip
                31  # Copy icon
            )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_search(self):
        """
        Delete the bulk prefix action from IDA.
        """
        idaapi.unregister_action(self.SEARCH)


# ------------------------------------------------------------------------------
# Plugin Hooks
# ------------------------------------------------------------------------------

class Hooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7)
        """
        inject_search_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0

    def finish_populating_tform_popup(self, form, popup):
        """
        A right click menu is about to be shown. (IDA 6.x)
        """
        inject_search_actions(form, popup, idaapi.get_tform_type(form))
        return 0

    def hxe_callback(self, event, *args):
        """
        HexRays event callback.
        We lump this under the (UI) Hooks class for organizational reasons.
        """

        #
        # if the event callback indicates that this is a popup menu event
        # (in the hexrays window), we may want to install our prefix menu
        # actions depending on what the cursor right clicked.
        #

        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args

            idaapi.attach_action_to_popup(
                form,
                popup,
                search_init.SEARCH,
                "Search MSDN",
                idaapi.SETMENU_APP,
            )

        # done
        return 0


# ------------------------------------------------------------------------------
# Prefix Wrappers
# ------------------------------------------------------------------------------


def inject_search_actions(form, popup, form_type):
    """
    Inject prefix actions to popup menu(s) based on context.
    """

    #
    # disassembly window
    #

    if form_type == idaapi.BWN_DISASMS:
        # insert the prefix action entry into the menu
        #

        idaapi.attach_action_to_popup(
            form,
            popup,
            search_init.SEARCH,
            "Search MSDN",
            idaapi.SETMENU_APP
        )

    # done
    return 0


# ------------------------------------------------------------------------------
# Byte copy
# ------------------------------------------------------------------------------

def search_web():
    """
    Copy selected bytes to clipboard
    """
    if using_ida7api:
        data = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
        print("%s" % data[0])
        page = requests.get('https://www.google.com/search?q=msdn+' + data[0])
        soup = BeautifulSoup(page.content, 'html.parser')
        # line below is long. if you need to fix it, here's what it does:
        # finds all <a> tags with an href that goes to microsoft.com
        # it then gets the 'href' portion, but that is way longer than we want, and has data before and after it
        # so we take off the beginning part (/url?q=) with the first split
        # and we take off everything after the actual url (more google junk that starts with '&') with the 2nd split
        msdn_page = soup.find('a', href=re.compile(r'https://docs.microsoft.com'))['href'].split("q=")[1].split('&')[0]
        webbrowser.open(msdn_page)
    else:
        data = idc.get_highlighted_identifier()
        print("%s" % data)
        page = requests.get('https://www.google.com/search?q=msdn+' + data[0])
        soup = BeautifulSoup(page.content, 'html.parser')
        # line below is long. if you need to fix it, here's what it does:
        # finds all <a> tags with an href that goes to microsoft.com
        # it then gets the 'href' portion, but that is way longer than we want, and has data before and after it
        # so we take off the beginning part (/url?q=) with the first split
        # and we take off everything after the actual url (more google junk that starts with '&') with the 2nd split
        msdn_page = soup.find('a', href=re.compile(r'https://docs.microsoft.com'))['href'].split("q=")[1].split('&')[0]
        webbrowser.open(msdn_page)
    return


# ------------------------------------------------------------------------------
# IDA ctxt
# ------------------------------------------------------------------------------

class IDACtxEntry(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS
