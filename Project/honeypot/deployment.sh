#!/bin/bash

python3 ./honeypot.py -d  "

88        88   ,ad8888ba,   888b      88 88888888888 8b        d8 88888888ba    ,ad8888ba, 888888888888  
88        88  d8''    ''8b  8888b     88 88           Y8,    ,8P  88      '8b  d8''    ''8b     88       
88        88 d8'        '8b 88 '8b    88 88            Y8,  ,8P   88      ,8P d8'        '8b    88       
88aaaaaaaa88 88          88 88  '8b   88 88aaaaa        '8aa8'    88aaaaaa8P' 88          88    88       
88''''''''88 88          88 88   '8b  88 88'''''         '88'     88'''''''   88          88    88       
88        88 Y8,        ,8P 88    '8b 88 88               88      88          Y8,        ,8P    88       
88        88  Y8a.    .a8P  88     '8888 88               88      88           Y8a.    .a8P     88                                                        _       __
88        88   ''Y8888Y''   88      '888 88888888888      88      88            ''Y8888Y''      88   Yb    dP 888888 88'''Yb .dP'Y8 88  dP'Yb  88b 88   //||    ||  ||
											              Yb  dP  88__   88__dP 'Ybo.   88 dP   Yb 88Yb88 =>  ||    ||  ||
                  									               YbdP   88''   88'Yb  o.'Y8b  88 Yb   dP 88 Y88    _||_,, ||__||  
                                                                                                        YP    888888 88  Yb 8bodP'  88  YbodP  88  Y8      



                    88 88b 88     888888 888888 .dP'Y8 888888 88 88b 88  dP''b8     88''Yb 88  88    db    .dP'Y8 888888 
                    88 88Yb88       88   88__   'Ybo.'   88   88 88Yb88 dP   ''     88__dP 88  88   dPYb   'Ybo.' 88__   
                    88 88 Y88       88   88''   o.'Y8b   88   88 88 Y88 Yb  '88     88'''  888888  dP__Yb  o.'Y8b 88''   
                    88 88  Y8       88   888888 8bodP'   88   88 88  Y8  YboodP     88     88  88 dP''''Yb 8bodP' 888888   @@@@@@@@@



                                                                        ...----....
 						                   ..-:'           '''-..
						                 .-'                      '-.
						               .'              .     .       '.
						             .'   .          .    .      .    .''.
						           .'  .    .       .   .   .     .   . ..:.
						         .' .   . .  .       .   .   ..  .   . ....::.
						        ..   .   .      .  .    .     .  ..  . ....:IA.
						       .:  .   .    .    .  .  .    .. .  .. .. ....:IA.
						      .: .   .   ..   .    .     . . .. . ... ....:.:VHA.
						      '..  .  .. .   .       .  . .. . .. . .....:.::IHHB.
						     .:. .  . .  . .   .  .  . . . ...:.:... .......:HIHMM.
						    .:.... .   . . :: '.. .   .  . .:.:.:II;,. .. ..:IHIMMA
						    ':.:..  ..::IHHHHHI::. . .  ...:.::::.,,,. . ....VIMMHM
						   .:::I. .AHHHHHHHHHHAI::. .:...,:IIHHHHHHMMMHHL:. . VMMMM
						  .:.:V.:IVHHHHHHHMHMHHH::..:  .:HIHHHHHHHHHHHHHMHHA. .VMMM.
						  ':..V.:IVHHHHHMMHHHHHHHB... . .:VPHHMHHHMMHHHHHHHHHAI.:VMMI
						  ::V..:VIHHHHHHMMMHHHHHH. .   .I:IIMHHMMHHHHHHHHHHHAPI:WMM
						  '::. .:.HHHHHHHHMMHHHHHI.  . .:..I:MHMMHHHHHHHHHMHV:':H:WM
						  :: . :.::IIHHHHHHMMHHHHV  .ABA.:.:IMHMHMMMHMHHHHV:'. .IHWW
						  '.  ..:..:.:IHHHHHMMHV' .AVMHMA.:.'VHMMMMHHHHHV:' .  :IHWV
						   :.  .:...: .:.:TPP'   .AVMMHMMA.:. 'VMMHHHP.:... .. :IVAI
						  .:.   '... .:''   .   ..HMMMHMMMA::. .'VHHI:::....  .:IHW'
						  ...  .  . ..:IIPPIH: ..HMMMI.MMMV:I:.  .:ILLH:.. ...:I:IM
						: .   .''' .:.V'. .. .  :HMMM:IMMMI::I. ..:HHIIPPHI::'.P:HM.
						:.  .  .  .. ..:.. .    :AMMM IMMMM..:...:IV':T::I::..:IHIMA
						'V:.. .. . .. .  .  .   'VMMV..VMMV :....:V:.:..:....::IHHHMH
						  'IHH:.II:.. .:. .  . . .   :HB'' . . ..PI:.::.:::..:IHHMMV'
						   :IP'''HHII:.  .  .    . . .'V:. . . ..:IH:.:.::IHIHHMMMMM
						   :V:. VIMA:I..  .     .  . .. . .  .:.I:I:..:IHHHHMMHHMMM
						   :VI:.VWMA::. .:      .   .. .:. ..:.I::.:IVHHHMMMHMMMMI
						   :.VIIHHMMA:.  .   .   .:  .:.. . .:.II:I:AMMMMMMHMMMMMI
						   :..VIHIHMMMI...::.,:.,:! I:! I! I! V:AI:VAMMMMMMHMMMMMM'
						   ':.:HIHIMHHA: !! I.:AXXXVVXXXXXXXA:. HPHIMMMMHHMHMMMMMV
						     V:H:I:MA:W'I :AXXXIXII:IIIISSSSSSXXA.I.VMMMHMHMMMMMM
						       'I::IVA ASSSSXSSSSBBSBMBSSSSSSBBMMMBS.VVMMHIMM'''
						        I:: VPAIMSSSSSSSSSBSSSMMBSSSBBMMMMXXI:MMHIMMI
						       .I::. H:XIIXBBMMMMMMMMMMMMMMMMMBXIXXMMPHIIMM
						       :::I.  ':XSSXXIIIIXSSBMBSSXXXIIIXXSMMAMI:.IMM
						       :::I:.  .VSSSSSISISISSSBII:ISSSSBMMB:MI:..:MM
						       ::.I:.  ':''SSSSSSSISISSXIIXSSSSBMMB:AHI:..MMM.
						       ::.I:. . ..:'BBSSSSSSSSSSSSBBBMMMB:AHHI::.HMMI
						       :..::.  . ..::':BBBBBSSBBBMMMB:MMMMHHII::IHHMI
						       ':.I:... ....:IHHHHHMMMMMMMMMMMMMMMHHIIIIHMMV'
						         V:. ..:...:.IHHHMMMMMMMMMMMMMMMMHHHMHHMHP
						          ':. .:::.:.::III::IHHHHMMMMMHMHMMHHHHM'
						            '::....::.:::..:..::IIIIIHHHHMMMHHMV'
						               ::.::.. .. .  ...:::IIHHMMMMHMV'
						                'V::... . .I::IHHMMV
						                  ''VHVHHHAHHHHMMV:'



" -ip 192.168.112.128 -p 80
