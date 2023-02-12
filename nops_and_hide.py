############################################################################################
## framework and IDA Plugin structure based on @herrcore's plugins
## NOPs!  
##
##
## To install:
##      Copy script into plugins directory, i.e: C:\Program Files\<ida version>\plugins
##
## To run:
##      Highlight disassembly instructions and right click and select "NOPs" 
##      The instructions will be automatically hidden.
##
############################################################################################
 
 
__AUTHOR__ = 'SplishSplash' # framework and IDA Plugin structure based on @herrcore's plugins 
 
PLUGIN_NAME = "NOPs"
PLUGIN_HOTKEY = 'Ctrl+U'
VERSION = '1.1.0'
 
 
import os
import sys
import idc
import idaapi
import idautils
import binascii
from idautils import *
from idc import *
 
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
    return make_nops()
 
class make_nops(idaapi.plugin_t):
    """
    The IDA Plugin for NOPs.
    """
 
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Copy Hex Bytes"
    help = "Highlight Assembly and right-click 'NOPs'"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
 
    #--------------------------------------------------------------------------
    # Plugin Overloads
    #--------------------------------------------------------------------------
 
    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """
 
        # initialize the menu actions our plugin will inject
        self._init_action_make_nops()
 
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
        self._del_action_make_nops()
 
 
        # done
        idaapi.msg("%s terminated...\n" % self.wanted_name)
 
    #--------------------------------------------------------------------------
    # Plugin Hooks
    #--------------------------------------------------------------------------
 
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
 
    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------
 
    ACTION_MAKE_NOPS  = "prefix:make_nops"
 
 
    def _init_action_make_nops(self):
        """
        Register the copy bytes action with IDA.
        """
        if (sys.version_info > (3, 0)):
            # Describe the action using python3 copy
            action_desc = idaapi.action_desc_t(
                self.ACTION_MAKE_NOPS,         # The action name.
                "NOPs",                        # The action text.
                IDACtxEntry(make_nops_py3),        # The action handler.
                PLUGIN_HOTKEY,                  # Optional: action shortcut
                "Make NOPs",                    # Optional: tooltip
                31                              # Copy icon
            )
        else:
            # Describe the action using python2 copy
            action_desc = idaapi.action_desc_t(
                self.ACTION_MAKE_NOPS,         # The action name.
                "NOPs",                     # The action text.
                IDACtxEntry(make_nops_py2),        # The action handler.
                PLUGIN_HOTKEY,                  # Optional: action shortcut
                "Copy selected bytes as hex",   # Optional: tooltip
                31                              # Copy icon
            )
 
 
        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"
 
 
    def _del_action_make_nops(self):
        """
        Delete the bulk prefix action from IDA.
        """
        idaapi.unregister_action(self.ACTION_MAKE_NOPS)
 
 
 
 
#------------------------------------------------------------------------------
# Plugin Hooks
#------------------------------------------------------------------------------
 
class Hooks(idaapi.UI_Hooks):
 
    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7)
        """
        inject_make_nops_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0
 
    def finish_populating_tform_popup(self, form, popup):
        """
        A right click menu is about to be shown. (IDA 6.x)
        """
        inject_make_nops_actions(form, popup, idaapi.get_tform_type(form))
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
                make_nops.ACTION_MAKE_NOPS,
                "NOPs",
                idaapi.SETMENU_APP,
            )
 
        # done
        return 0
 
#------------------------------------------------------------------------------
# Prefix Wrappers
#------------------------------------------------------------------------------
 
 
def inject_make_nops_actions(form, popup, form_type):
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
            make_nops.ACTION_MAKE_NOPS,
            "NOPs",
            idaapi.SETMENU_APP
        )
 
    # done
    return 0
 
#------------------------------------------------------------------------------
# IDB Modification
#------------------------------------------------------------------------------
 
def make_nops_py2():
    """
    Copy selected bytes to clipboard
    """
    if using_ida7api:
        start = idc.read_selection_start()
        end = idc.read_selection_end()
        if idaapi.BADADDR in (start, end):
            ea = idc.here()
            start = idaapi.get_item_head(ea)
            end = idaapi.get_item_end(ea)
        data = idc.get_bytes(start, end - start).encode('hex')
        for i, n in enumerate(data):
            idaapi.patch_byte(start+i, 0x90)
            ida_nalt.hide_item(start+i)
 
def make_nops_py3():
    """
    Copy selected bytes to clipboard
    """
    if using_ida7api:
        start = idc.read_selection_start()
        end = idc.read_selection_end()
        if idaapi.BADADDR in (start, end):
            ea = idc.here()
            start = idaapi.get_item_head(ea)
            end = idaapi.get_item_end(ea)
        # fix encode bug reference 
        # https://stackoverflow.com/questions/6624453/whats-the-correct-way-to-convert-bytes-to-a-hex-string-in-python-3
        data = idc.get_bytes(start, end - start).hex()
        for i, n in enumerate(data):
            idaapi.patch_byte(start+i, 0x90)
            ida_nalt.hide_item(start+i)
 
#------------------------------------------------------------------------------
# IDA ctxt
#------------------------------------------------------------------------------
 
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
 
