PROC=patchdiff
O1=backup
O2=clist
O3=diff
O4=hash
O5=archi
O6=options
O7=parser
O8=pchart
O9=pgraph
O10=sig
O11=system
012=display

__LINUX__ = 1

include ../plugin.unx

# MAKEDEP dependency list ------------------
$(F)archi$(O)   : $(I)ida.hpp $(I)bytes.hpp $(I)kernwin.hpp patchdiff.hpp   \
	          ppc.hpp x86.hpp ppc.cpp x86.cpp
$(F)backup$(O)  : $(I)ida.hpp sig.hpp diff.hpp options.hpp backup.hpp       \
	          backup.cpp
$(F)clist$(O)   : $(I)ida.hpp sig.hpp hash.hpp clist.hpp clist.cpp
$(F)diff$(O)    : $(I)ida.hpp $(I)idp.hpp $(I)graph.hpp $(I)kernwin.hpp     \
	          diff.hpp sig.hpp os.hpp clist.hpp display.hpp backup.hpp  \
	          options.hpp diff.cpp
$(F)display$(O) : $(I)ida.hpp $(I)idp.hpp $(I)graph.hpp $(I)kernwin.hpp     \
	          diff.hpp system.hpp os.hpp parser.hpp pgraph.hpp          \
	          options.hpp display.hpp display.cpp
$(F)hash$(O)    : $(I)ida.hpp sig.hpp hash.hpp hash.cpp
$(F)options$(O) : $(I)ida.hpp $(I)kernwin.hpp system.hpp options.hpp        \
	          options.cpp
$(F)parser$(O)  : $(I)ida.hpp $(I)pro.h $(I)funcs.hpp $(I)fpro.h            \
	          $(I)diskio.hpp $(I)kernwin.hpp parser.hpp sig.hpp         \
	          os.hpp pchart.hpp system.hpp display.cpp
$(F)patchdiff$(O)  : $(I)ida.hpp $(I)loader.hpp $(I)kernwin.hpp             \
	          $(I)diskio.hpp $(I)idp.hpp $(I)auto.hpp parser.hpp sig.hpp\
	          patchdiff.hpp diff.hpp backup.hpp display.hpp options.hpp \
	          system.hpp patchdiff.cpp
$(F)pchart$(O)  : $(I)ida.hpp $(I)pro.h $(I)funcs.hpp                       \
	          $(I)gdl.hpp $(I)xref.hpp pchart.hpp patchdiff.hpp         \
	          x86.hpp pchart.cpp
$(F)pgraph$(O)  : $(I)ida.hpp $(I)idp.hpp $(I)graph.hpp $(I)kernwin.hpp     \
	          sig.hpp diff.hpp pgraph.hpp pgraph.cpp
$(F)sig$(O)     : $(I)pro.h $(I)ida.hpp $(I)xref.hpp $(I)gdl.hpp            \
	          $(I)bytes.hpp $(I)funcs.hpp $(I)kernwin.hpp $(I)fpro.h    \
	          $(I)diskio.hpp $(I)name.hpp $(I)ua.hpp $(I)demangle.hpp   \
	          $(I)graph.hpp sig.hpp x86.hpp ppc.hpp patchdiff.hpp       \
	          pchart.hpp sig.cpp
$(F)system$(O)  : $(I)ida.hpp $(I)pro.h $(I)fpro.h $(I)diskio.hpp           \
	          $(I)kernwin.hpp sig.hpp system.hpp options.hpp os.hpp     \
	          system.cpp
