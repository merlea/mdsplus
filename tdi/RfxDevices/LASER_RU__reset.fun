public fun LASER_RU__reset(as_is _nid, optional _method)
{
    private _K_CONG_NODES = 67;

	private _N_COMMENT = 1;
    private _N_RS232_PORT = 2;
    private _N_TRIG_MODE = 3;
    private _N_NUM_SHOTS = 4;
    private _N_ENERGY = 5;
    private _N_VOLTAGE_OSC = 6;
    private _N_VOLTAGE_A_1 = 7;
    private _N_VOLTAGE_A_2 = 8;
    private _N_VOLTAGE_A_3 = 9;

    private _N_BALANCE_P_1 = 10;
    private _N_BALANCE_P_2 = 11;
    private _N_BALANCE_P_3 = 12;

    private _N_DELAY_AMP = 13;
    private _N_DELAY_PULS_1 = 14;
    private _N_DELAY_PULS_2 = 15;
    private _N_DELAY_PULS_3 = 16;
    private _N_DELAY_PULS_4 = 17;
    private _N_DELAY_FIRE = 18;

    private _N_CALIBRATION = 19;
    private _N_CAL_KOSC = 20;
    private _N_CAL_KAMP_1 = 21;
    private _N_CAL_KAMP_2 = 22;
    private _N_CAL_KAMP_3 = 23;
    private _N_CAL_KBAL_1 = 24;
    private _N_CAL_KBAL_2 = 25;
    private _N_CAL_KBAL_3 = 26;

    private _N_OSC_PAR = 27;
	private _N_AMP_PAR_1 = 28;
    private _N_AMP_PAR_2 = 29;
    private _N_AMP_PAR_3 = 30;
    private _N_PBAL_PAR_1 = 31;
    private _N_PBAL_PAR_2 = 32;
    private _N_PBAL_PAR_3 = 33;

    private _N_DTIME1_PAR_1 = 34;
    private _N_DTIME1_PAR_2 = 35;
    private _N_DTIME1_PAR_3 = 36;
    private _N_DTIME1_PAR_4 = 37;
    private _N_DTIME1_PAR_4 = 38;
    private _N_DF1M_PAR_1 = 39;
    private _N_DF1M_PAR_2 = 40;

    private _K_NUM_BITS = 5;
    private _K_NODES_PER_BIT = 2;
    private _N_BIT_0= 42;
    private _N_BIT_PRE_SHOT = 1;
    private _N_BIT_POST_SHOT = 1;

	private _N_DATA = 63;

	private _RS232_XONXOFF = 0;
    private _RS232_CTSDSR  = 1;

    private _TRIG_INTERNAL  = 0;
    private _TRIG_EXTERNAL  = 2;
    private _TRIG_AUTOMATIC = 3;
    private _TRIG_MANUAL    = 4;


   private fun SendCommand(in _hComm, in _nid, in _cmnd)
	{
		_outValue = 0;
		_error = LASER_RUSendCommand(_hComm,  _cmnd, size(_cmnd), in _outValue);
		if(_error <= 0)
		{
			if(_error == 0)
			{
    			DevLogErr(_nid, "RS232 communication error : "//RS232GetError() );
				RS232Close(_hComm);
				return (-1);
			}
    		DevLogErr(_nid, "Ruby laser execution command error : "//_cmnd);
		}
		return ( _outValue );
	};

    _port = if_error(data(DevNodeRef(_nid, _N_RS232_PORT)),(DevLogErr(_nid, "Missing RS232 Port"); abort();));

    _hComm = RS232OpenPort(_port, "baud=1200 parity=N data=8 stop=1", 0, _RS232_XONXOFF, 13);
	if( _hComm == 0 )
	{
    	DevLogErr(_nid, "Cannot open RS232 port : "//RS232GetError() );
		abort();
	}


	/* Get status digital output lines */

    _bit_states = [];
    for(_i = 0; _i < _K_NUM_BITS; _i++)
    {
 		_bit_state = if_error(data(DevNodeRef(_nid, _N_BIT_0  + ( _i *  _K_NODES_PER_BIT) +  _N_BIT_POST_SHOT)), _bit_state = 0);
		_bit_states = [_bit_states, _bit_state];
    }


/* Set all digital output */
    for(_i = 0, _bit = 0; _i < _K_NUM_BITS; _i++, _bit++)
	{
		if(i == 3) _bit++;

		if(_bit_states[i])
			_cmnd =  "on "//_bit;
		else
			_cmnd =  "off "//_bit;

		if( SendCommand(_hComm, _nid,  _cmnd) < 0 ) abort();
    }


/* Read analog input */
	_data = [];
    for( _i = 0; _i < _K_NUM_DATA; i++)
	{
		_cmnd = "adc "//_i;
		_val = SendCommand(_hComm, _nid,  _cmnd);
		if( _val < 0 ) abort();
		_data = [_data, _val];
    }

	_cmnd = "hip";
	_retvalue = SendCommand(_hComm, _nid,  _cmnd);
	if(_retvalue < 0) abort();

	if(retvalue == 49) 
	{
/* Dump sequence */
		_cmnd =  "dtime1 2 2 2 2";
		if( SendCommand(_hComm, _nid,  _cmnd) < 0 ) abort();

		_cmnd =  "use1";
		if( SendCommand(_hComm, _nid,  _cmnd) < 0 ) abort();

		_cmnd =  "dump 0";
		if( SendCommand(_hComm, _nid,  _cmnd) < 0 ) abort();

		_cmnd =  "charge 0";
		if( SendCommand(_hComm, _nid,  _cmnd) < 0 ) abort();

		wait(1.0);

	}

	DevPut(_nid, _N_DATA, _data);

	RS232Close(_hComm);

	return (1);

}















