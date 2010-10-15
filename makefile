PROC=patchdiff
O1=backup
O2=clist
O3=diff
O4=hash
O5=ppc
O6=x86
O7=options
O8=parser
O9=pchart
O10=pgraph
O11=sig
O12=system
O13=display
O14=unix_fct

__LINUX__ = 1

include ../plugin.unx

# MAKEDEP dependency list ------------------
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
$(F)ppc$(O)     : $(I)ida.hpp $(I)bytes.hpp $(I)kernwin.hpp patchdiff.hpp   \
	          ppc.hpp ppc.cpp
$(F)sig$(O)     : $(I)pro.h $(I)ida.hpp $(I)xref.hpp $(I)gdl.hpp            \
	          $(I)bytes.hpp $(I)funcs.hpp $(I)kernwin.hpp $(I)fpro.h    \
	          $(I)diskio.hpp $(I)name.hpp $(I)ua.hpp $(I)demangle.hpp   \
	          $(I)graph.hpp sig.hpp x86.hpp ppc.hpp patchdiff.hpp       \
	          pchart.hpp sig.cpp
$(F)system$(O)  : $(I)ida.hpp $(I)pro.h $(I)fpro.h $(I)diskio.hpp           \
	          $(I)kernwin.hpp sig.hpp system.hpp options.hpp os.hpp     \
	          system.cpp
$(F)unix_fct(O) : $(I)ida.hpp $(I)kernwin.hpp $(I)system.hpp                \
	          unix_fct.hpp unix_fct.cpp
$(F)x86$(O)     : $(I)ida.hpp $(I)bytes.hpp $(I)kernwin.hpp patchdiff.hpp   \
	          x86.hpp x86.cpp
