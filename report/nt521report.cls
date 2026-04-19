%% nt521report.cls — Custom LaTeX class for NT521 course report
%% Author: NT521 Group – UIT
%% Date: 2026
%%
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{nt521report}[2026/04/20 NT521 Report Class]

%% Base class
\LoadClass[a4paper,12pt,oneside]{report}

%% ─── Encoding & Vietnamese ──────────────────────────────────────────────────
\RequirePackage[utf8]{inputenc}
\RequirePackage[T5]{fontenc}
\RequirePackage[vietnamese]{babel}

%% ─── Geometry ───────────────────────────────────────────────────────────────
\RequirePackage[
  left   = 3cm,
  right  = 2cm,
  top    = 2.5cm,
  bottom = 2.5cm,
]{geometry}

%% ─── Fonts ──────────────────────────────────────────────────────────────────
\RequirePackage{lmodern}
\RequirePackage{microtype}

%% ─── Math & Symbols ────────────────────────────────────────────────────────
\RequirePackage{amsmath,amssymb,amsfonts}

%% ─── Graphics & Colors ─────────────────────────────────────────────────────
\RequirePackage{graphicx}
\RequirePackage[table,dvipsnames,svgnames]{xcolor}
\RequirePackage{tikz}
\usetikzlibrary{
  arrows.meta,
  shapes.geometric,
  shapes.misc,
  positioning,
  calc,
  fit,
  backgrounds,
  decorations.pathreplacing,
  chains,
  matrix,
  patterns,
  shadows,
}

%% ─── Tables ─────────────────────────────────────────────────────────────────
\RequirePackage{booktabs}
\RequirePackage{tabularx}
\RequirePackage{multirow}
\RequirePackage{longtable}
\RequirePackage{array}

%% ─── Listings / Code ───────────────────────────────────────────────────────
\RequirePackage{listings}
\RequirePackage{minted}

\lstset{
  basicstyle     = \ttfamily\small,
  keywordstyle   = \bfseries\color{MidnightBlue},
  commentstyle   = \itshape\color{Gray},
  stringstyle    = \color{OliveGreen},
  numbers        = left,
  numberstyle    = \tiny\color{Gray},
  numbersep      = 8pt,
  frame          = single,
  framerule       = 0.4pt,
  rulecolor       = \color{Gray!50},
  backgroundcolor = \color{Gray!5},
  breaklines     = true,
  breakatwhitespace = true,
  showstringspaces = false,
  tabsize        = 4,
  captionpos     = b,
  aboveskip      = 10pt,
  belowskip      = 8pt,
  xleftmargin    = 15pt,
  xrightmargin   = 5pt,
}

\lstdefinestyle{Python}{
  language        = Python,
  morekeywords    = {self,yield,async,await,True,False,None},
}

\lstdefinestyle{JSON}{
  morestring     = [b]",
  stringstyle    = \color{OliveGreen},
  literate       =
    *{0}{{{\color{Maroon}0}}}{1}
     {1}{{{\color{Maroon}1}}}{1}
     {2}{{{\color{Maroon}2}}}{1}
     {3}{{{\color{Maroon}3}}}{1}
     {4}{{{\color{Maroon}4}}}{1}
     {5}{{{\color{Maroon}5}}}{1}
     {6}{{{\color{Maroon}6}}}{1}
     {7}{{{\color{Maroon}7}}}{1}
     {8}{{{\color{Maroon}8}}}{1}
     {9}{{{\color{Maroon}9}}}{1},
}

%% ─── Hyperrefs ──────────────────────────────────────────────────────────────
\RequirePackage[
  colorlinks = true,
  linkcolor  = MidnightBlue,
  citecolor  = OliveGreen,
  urlcolor   = RoyalBlue,
]{hyperref}

%% ─── Bibliography ───────────────────────────────────────────────────────────
\RequirePackage[
  backend   = biber,
  style     = numeric,
  sorting   = nyt,
  maxnames  = 3,
]{biblatex}

%% ─── Captions & Floats ─────────────────────────────────────────────────────
\RequirePackage[font=small, labelfont=bf]{caption}
\RequirePackage{subcaption}
\RequirePackage{float}

%% ─── Header / Footer ───────────────────────────────────────────────────────
\RequirePackage{fancyhdr}
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\small\nouppercase{\leftmark}}
\fancyhead[R]{\small NT521 -- An toàn ứng dụng}
\fancyfoot[C]{\thepage}
\renewcommand{\headrulewidth}{0.4pt}
\renewcommand{\footrulewidth}{0pt}

%% ─── Chapter style ─────────────────────────────────────────────────────────
\RequirePackage{titlesec}
\titleformat{\chapter}[display]
  {\normalfont\Huge\bfseries\color{MidnightBlue}}
  {\chaptertitlename\ \thechapter}{20pt}{\Huge}
\titlespacing*{\chapter}{0pt}{-20pt}{30pt}

\titleformat{\section}
  {\normalfont\Large\bfseries\color{MidnightBlue!80!black}}
  {\thesection}{1em}{}
\titleformat{\subsection}
  {\normalfont\large\bfseries\color{MidnightBlue!60!black}}
  {\thesubsection}{1em}{}
\titleformat{\subsubsection}
  {\normalfont\normalsize\bfseries}
  {\thesubsubsection}{1em}{}

%% ─── Spacing ────────────────────────────────────────────────────────────────
\RequirePackage{setspace}
\onehalfspacing
\setlength{\parindent}{1.5em}
\setlength{\parskip}{0.5em}

%% ─── Enumerate / Itemize ───────────────────────────────────────────────────
\RequirePackage{enumitem}
\setlist[itemize]{topsep=4pt, itemsep=2pt, parsep=0pt}
\setlist[enumerate]{topsep=4pt, itemsep=2pt, parsep=0pt}

%% ─── Boxes ──────────────────────────────────────────────────────────────────
\RequirePackage[most]{tcolorbox}

\newtcolorbox{notebox}[1][]{
  colback    = blue!5,
  colframe   = MidnightBlue,
  fonttitle  = \bfseries,
  title      = {Ghi chú},
  #1
}

\newtcolorbox{warningbox}[1][]{
  colback    = red!5,
  colframe   = red!70!black,
  fonttitle  = \bfseries,
  title      = {Cảnh báo},
  #1
}

\newtcolorbox{infobox}[1][]{
  colback    = green!5,
  colframe   = OliveGreen,
  fonttitle  = \bfseries,
  title      = {Thông tin},
  #1
}

\newtcolorbox{defbox}[1][]{
  colback    = gray!5,
  colframe   = gray!60!black,
  fonttitle  = \bfseries,
  title      = {Định nghĩa},
  #1
}

%% ─── Misc ───────────────────────────────────────────────────────────────────
\RequirePackage{pdfpages}
\RequirePackage{appendix}
\RequirePackage{glossaries}

%% ─── Custom commands ────────────────────────────────────────────────────────
\newcommand{\code}[1]{\texttt{#1}}
\newcommand{\keyword}[1]{\textbf{\textit{#1}}}
\newcommand{\projectname}{HonestCyberEval}
\newcommand{\reflexion}{\textsc{Reflexion}}

\endinput
