package com.soffid.iam.agent.oracle;

import java.math.BigDecimal;
import java.net.InetAddress;
import java.rmi.RemoteException;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.soffid.iam.api.AccessControl;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.AccountStatus;
import com.soffid.iam.api.Group;
import com.soffid.iam.api.ObjectMappingTrigger;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.Role;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.SoffidObjectType;
import com.soffid.iam.api.SystemAccessControl;
import com.soffid.iam.api.User;
import com.soffid.iam.sync.intf.ExtensibleObjectMgr;

import es.caib.seycon.ng.comu.SoffidObjectTrigger;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.bootstrap.NullSqlObjet;
import es.caib.seycon.ng.sync.bootstrap.QueryHelper;
import es.caib.seycon.ng.sync.intf.LogEntry;
import oracle.jdbc.driver.OracleTypes;

import com.soffid.iam.sync.agent.Agent;
import com.soffid.iam.sync.engine.extobj.AccountExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ExtensibleObjectFinder;
import com.soffid.iam.sync.engine.extobj.GrantExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ObjectTranslator;
import com.soffid.iam.sync.engine.extobj.RoleExtensibleObject;
import com.soffid.iam.sync.engine.extobj.UserExtensibleObject;
import com.soffid.iam.sync.intf.AccessControlMgr;
import com.soffid.iam.sync.intf.AccessLogMgr;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObjectMapping;
import com.soffid.iam.sync.intf.ReconcileMgr2;
import com.soffid.iam.sync.intf.RoleMgr;
import com.soffid.iam.sync.intf.UserMgr;

/**
 * Agente SEYCON para gestionar bases de datos Oracle
 * <P>
 */

public class OracleAgent extends Agent implements UserMgr, RoleMgr,
		AccessControlMgr, AccessLogMgr, ReconcileMgr2, ExtensibleObjectMgr {
	private static final String PASSWORD_QUOTE_REPLACEMENT = "'";
	/** Usuario Oracle */
	transient String user;
	/** Contraseña oracle */
	transient Password password;
	/** Cadena de conexión a la base de datos */
	transient String db;
	/** Contraseña con la que proteger el rol */
	transient Password rolePassword;
	private String defaultProfile;
	/** Define el espacio de tabla por defecto*/
	private String defaultTablespace;
	/** Define el espacio de tabla temporal*/
	private String temporaryTablespace;
	/** Valor que activa o desactiva el debug */
	transient boolean debug;
	/**
	 * Hash de conexiones ya establecidas. De esta forma se evita que el agente
	 * seycon abra conexiones sin control debido a problemas de comunicaciones
	 * con el servidor
	 */
	static Hashtable hash = new Hashtable();

	/* versió dels triggers del control d'accés */
	private final static String VERSIO = "1.2"; //$NON-NLS-1$

	/**
	 * Constructor
	 * 
	 * @param params
	 *            vector con parámetros de configuración: <LI>0 = usuario</LI>
	 *            <LI>1 = contraseña oracle</LI> <LI>2 = cadena de conexión a la
	 *            base de datos</LI> <LI>3 = contraseña con la que se protegerán
	 *            los roles</LI>
	 */
	public OracleAgent() throws java.rmi.RemoteException {
		super();
	}

	/**
	 * Crea las tablas y los triggers (deshabilitados) de control de acceso
	 * 
	 * @throws java.rmi.RemoteException
	 * @throws es.caib.seycon.InternalErrorException
	 */
	private void createAccessControl() throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		PreparedStatement stmtCAC = null;
		PreparedStatement stmt = null;
		ResultSet rsetCAC = null;
		try {
			Connection sqlConnection = getConnection();

			// Comprobamos que exista la tabla de roles de control de acceso
			// SC_OR_ACCLOG: tabla de logs
			stmtCAC = sqlConnection
					.prepareStatement(sentence("select 1 from user_tables where upper(table_name) ='SC_OR_ACCLOG'", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				int anyo = Calendar.getInstance().get(Calendar.YEAR);
				// La creamos PARTICIONADA para el año actual
				String cmd = "create table SC_OR_ACCLOG  ( " + //$NON-NLS-1$
						"   sac_user_id		varchar2(50 CHAR),"
						+ //$NON-NLS-1$
						"   sac_session_Id	varchar2(50 CHAR),"
						+ //$NON-NLS-1$
						"   sac_process		varchar2(50 CHAR),"
						+ //$NON-NLS-1$
						"   sac_host		varchar2(50 CHAR),"
						+ //$NON-NLS-1$
						"   sac_logon_day	date,"
						+ //$NON-NLS-1$
						"   sac_os_user		varchar2(50 CHAR),"
						+ //$NON-NLS-1$
						"   sac_program		varchar2(80 CHAR)"
						+ //$NON-NLS-1$
//						" ) "
//						+ //$NON-NLS-1$
//						" partition by range (sac_logon_day) "
//						+ //$NON-NLS-1$
//						" ( "
//						+ //$NON-NLS-1$
//						"   partition SC_OR_ACCLOG_p"
//						+ anyo
//						+ " values less than (to_date('01/01/" + (anyo + 1) + "','DD/MM/YYYY')), " + //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
//						"   partition SC_OR_ACCLOG_otros values less than (maxvalue) "
//						+ //$NON-NLS-1$
						" )"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(sentence(cmd,null));
				stmt.execute();
				stmt.close();
				if (debug) log.info("Created table 'SC_OR_ACCLOG', year {}", anyo, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// SC_OR_CONACC
			stmtCAC = sqlConnection
					.prepareStatement(sentence("select 1 from user_tables where upper(table_name) ='SC_OR_CONACC'", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				String cmd = "CREATE TABLE SC_OR_CONACC  ( " + //$NON-NLS-1$
						"  SOC_USER VARCHAR2(50 CHAR) " + //$NON-NLS-1$
						", SOC_ROLE VARCHAR2(50 CHAR) " + //$NON-NLS-1$
						", SOC_HOST VARCHAR2(50 CHAR)" + //$NON-NLS-1$
						", SOC_PROGRAM VARCHAR2(80 CHAR) " + //$NON-NLS-1$
						", SOC_CAC_ID  NUMBER(10,0) " + //$NON-NLS-1$
						", SOC_HOSTNAME  VARCHAR2(50 CHAR) " + //$NON-NLS-1$
						")"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(sentence(cmd, null));
				stmt.execute();
				stmt.close();
				if (debug) log.info("Created table 'SC_OR_CONACC'", null, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// SC_OR_ROLE
			stmtCAC = sqlConnection
					.prepareStatement(sentence("select 1 from user_tables where upper(table_name) ='SC_OR_ROLE'",null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				String cmd = "CREATE TABLE SC_OR_ROLE  ( " //$NON-NLS-1$
						+ "  	SOR_GRANTEE VARCHAR2(50 CHAR) NOT NULL " //$NON-NLS-1$
						+ " 	, SOR_GRANTED_ROLE VARCHAR2(50 CHAR) NOT NULL " //$NON-NLS-1$
						+ "	, CONSTRAINT SC_OR_ROLE_PK PRIMARY KEY " //$NON-NLS-1$
						+ "  	( SOR_GRANTEE, SOR_GRANTED_ROLE ) ENABLE " //$NON-NLS-1$
						+ ")"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(sentence(cmd, null));
				stmt.execute();
				stmt.close();
				if (debug) log.info("Created table 'SC_OR_ROLE'", null, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// SC_OR_VERSIO
			stmtCAC = sqlConnection
					.prepareStatement(sentence("select 1 from user_tables where upper(table_name) ='SC_OR_VERSIO'", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				String cmd = "CREATE TABLE SC_OR_VERSIO  ( " //$NON-NLS-1$
						+ "  SOV_VERSIO VARCHAR2(20 CHAR) " //$NON-NLS-1$
						+ ", SOV_DATA DATE DEFAULT SYSDATE " + ")"; //$NON-NLS-1$ //$NON-NLS-2$
				stmt = sqlConnection.prepareStatement(sentence(cmd, null));
				stmt.execute();
				stmt.close();
				if (debug) log.info("Created table 'SC_OR_VERSIO'", null, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// Ací comprovem que la versió dels triggers corresponga amb la
			// versió actual
			boolean actualitzaTriggers = false; // Per defecte NO s'actualitzen
			// obtenim la darrera versió del trigger
			stmtCAC = sqlConnection
					.prepareStatement(sentence("select SOV_VERSIO from SC_OR_VERSIO where sov_data = (select max(SOV_DATA) from SC_OR_VERSIO)", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			// Mirem si no existeix cap fila o si la versió és diferent a la
			// actual
			if (!rsetCAC.next()) {
				// No existeix cap, actualitzem i inserim una fila
				actualitzaTriggers = true;
				String cmd = "insert into SC_OR_VERSIO (SOV_VERSIO) VALUES (?)"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(sentence(cmd, null));
				stmt.setString(1, VERSIO);
				stmt.execute();
				stmt.close();
				if (debug) log.info("Detected different agent version, triggers will be updated", null, null); //$NON-NLS-1$
			} else {
				String versioActual = rsetCAC.getString(1);
				if (!VERSIO.equals(versioActual)) {
					// És una versió diferent, l'hem d'actualitzar
					actualitzaTriggers = true;
					// Guardem la versió actual
					String cmd = "insert into SC_OR_VERSIO (SOV_VERSIO) VALUES (?)"; //$NON-NLS-1$
					stmt = sqlConnection.prepareStatement(sentence(cmd, null));
					stmt.setString(1, VERSIO);

					stmt.execute();
					stmt.close();
					if (debug) log.info("Detected different agent version, triggers will be updated", null, null); //$NON-NLS-1$
				}
			}
			rsetCAC.close();
			stmtCAC.close();

			// TRIGGERS DE LOGON Y LOGOFF
			// LOGON
			stmtCAC = sqlConnection
					.prepareStatement(sentence("select 1 from user_triggers where upper(TRIGGER_NAME) ='LOGON_AUDIT_TRIGGER'", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			boolean existeLogonTrigger = rsetCAC.next();

			if (!existeLogonTrigger || actualitzaTriggers) {

				if (existeLogonTrigger && actualitzaTriggers) {
					// Lo desactivamos (para actualizarlo)
					stmt = sqlConnection
							.prepareStatement(sentence("alter trigger logon_audit_trigger disable", null)); //$NON-NLS-1$
					stmt.execute();
					stmt.close();
					if (debug) log.info("Disabled 'LOGON_AUDIT_TRIGGER' to updated it", null, null); //$NON-NLS-1$
				}

				// Creamos o reemplazamos el TRIGGER:
				String cmd = "create or replace TRIGGER logon_audit_trigger AFTER logon ON database \n" + //$NON-NLS-1$
						"  DECLARE \n"
						+ //$NON-NLS-1$
						"    seycon_accesscontrol_exception exception; \n"
						+ //$NON-NLS-1$
						"    User                         VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    programa                       VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    p_host                         VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    osuser                         VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    process                        VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    sessionid                      VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    ipaddress                      VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    existe                         INTEGER; \n"
						+ //$NON-NLS-1$
						"   begin \n"
						+ //$NON-NLS-1$
						"     /* NO FEM LOG DE L'User SYS A LOCALHOST */ \n"
						+ //$NON-NLS-1$
						"    --   if (UPPER(User) IN ('SYS') AND IPADDRESS='127.0.0.1') THEN RETURN; END IF;\n"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"    /*OBTENEMOS PARAMETROS DEL USUARIO*/ \n"
						+ //$NON-NLS-1$
						"    select user into User from DUAL; \n"
						+ //$NON-NLS-1$
						"    SELECT nvl(SYS_CONTEXT('USERENV','IP_ADDRESS'),'127.0.0.1') INTO IPADDRESS FROM DUAL; \n"
						+ //$NON-NLS-1$
						"    select nvl(module,' ') INTO programa from v$session where audsid = userenv('sessionid') and username is not null and sid=(select SID from v$mystat where rownum=1); \n"
						+ //$NON-NLS-1$
						"    SELECT SYS_CONTEXT('USERENV','OS_USER') INTO osuser from dual; \n"
						+ //$NON-NLS-1$
						"    select SYS_CONTEXT('USERENV','SESSIONID') into SESSIONID from DUAL; \n"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"     /*VERIFICAMOS ENTRADA: */ \n"
						+ //$NON-NLS-1$
						"    if (UPPER(User) in ('SYS','SYSTEM')) then EXISTE:=1; /*PROCESOS DE ESTOS USUARIOS (SIN SER DBA)*/ \n"
						+ //$NON-NLS-1$
						"    else \n"
						+ //$NON-NLS-1$
						"      select COUNT(*) INTO EXISTE from sc_or_conacc \n"
						+ //$NON-NLS-1$
						"      where ( soc_user is null or upper(User) like upper(soc_user)) \n"
						+ //$NON-NLS-1$
						"       and \n"
						+ //$NON-NLS-1$
						"      ( soc_role is null \n"
						+ //$NON-NLS-1$
						"        OR EXISTS \n"
						+ //$NON-NLS-1$
						"        (select 1 from sc_or_role where sor_grantee=User and sor_granted_role = soc_role) \n"
						+ //$NON-NLS-1$
						"      ) \n"
						+ //$NON-NLS-1$
						"      and (IPADDRESS like SOC_HOST) and (UPPER(PROGRAMA) like UPPER(SOC_PROGRAM)); \n"
						+ //$NON-NLS-1$
						"    END IF; \n"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"    /* VERIFICAMOS ENTRADA*/ \n"
						+ //$NON-NLS-1$
						"    IF EXISTE=0 THEN \n"
						+ //$NON-NLS-1$
						"      savepoint START_LOGGING_ERROR; \n"
						+ //$NON-NLS-1$
						"      insert into SC_OR_ACCLOG ( \n"
						+ //$NON-NLS-1$
						"        SAC_USER_ID, \n"
						+ //$NON-NLS-1$
						"        SAC_SESSION_ID, \n"
						+ //$NON-NLS-1$
						"        SAC_PROCESS, \n"
						+ //$NON-NLS-1$
						"        SAC_HOST, \n"
						+ //$NON-NLS-1$
						"        SAC_LOGON_DAY, \n"
						+ //$NON-NLS-1$
						"        SAC_OS_USER, \n"
						+ //$NON-NLS-1$
						"        SAC_PROGRAM \n"
						+ //$NON-NLS-1$
						"      \n)"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"      SELECT \n"
						+ //$NON-NLS-1$
						"        User,     	/* user_id */ \n"
						+ //$NON-NLS-1$
						"        sessionid,     /* session_id */ \n"
						+ //$NON-NLS-1$
						"        'not-allowed', /* process */ \n"
						+ //$NON-NLS-1$
						"        ipaddress,     /* host */ \n"
						+ //$NON-NLS-1$
						"        Sysdate,       /* LOGON_DAY */ \n"
						+ //$NON-NLS-1$
						"        osuser,        /* OSUSER */ \n"
						+ //$NON-NLS-1$
						"        PROGRAMA       /* PROGRAM */ \n"
						+ //$NON-NLS-1$
						"      FROM dual; \n"
						+ //$NON-NLS-1$
						"      commit; \n"
						+ //$NON-NLS-1$
						"      Raise SEYCON_ACCESSCONTROL_EXCEPTION; \n"
						+ //$NON-NLS-1$
						"    ELSE \n"
						+ //$NON-NLS-1$
						"      /* registrem el logon correcte */ \n"
						+ //$NON-NLS-1$
						"      INSERT INTO SC_OR_ACCLOG ( \n"
						+ //$NON-NLS-1$
						"        SAC_USER_ID, \n"
						+ //$NON-NLS-1$
						"        SAC_SESSION_ID, \n"
						+ //$NON-NLS-1$
						"        SAC_PROCESS, \n"
						+ //$NON-NLS-1$
						"        SAC_HOST, \n"
						+ //$NON-NLS-1$
						"        SAC_LOGON_DAY, \n"
						+ //$NON-NLS-1$
						"        SAC_OS_USER, \n"
						+ //$NON-NLS-1$
						"        SAC_PROGRAM \n"
						+ //$NON-NLS-1$
						"      ) \n"
						+ //$NON-NLS-1$
						"      SELECT \n"
						+ //$NON-NLS-1$
						"        User, 	/* user_id  */ \n"
						+ //$NON-NLS-1$
						"        sessionid, /* session_id */ \n"
						+ //$NON-NLS-1$
						"        'logon',   /* process */ \n"
						+ //$NON-NLS-1$
						"        ipaddress, /* host */ \n"
						+ //$NON-NLS-1$
						"        Sysdate,   /* LOGON_DAY */ \n"
						+ //$NON-NLS-1$
						"        osuser,    /* OSUSER */ \n"
						+ //$NON-NLS-1$
						"        Programa   /* PROGRAM */ \n"
						+ //$NON-NLS-1$
						"      FROM DUAL; \n"
						+ //$NON-NLS-1$
						"    end if; \n"
						+ //$NON-NLS-1$
						"  EXCEPTION \n"
						+ //$NON-NLS-1$
						"  when SEYCON_ACCESSCONTROL_EXCEPTION then \n"
						+ //$NON-NLS-1$
						"    RAISE_APPLICATION_ERROR (-20000, 'LOGON Error: You are not allowed to connect to this database '); \n"
						+ //$NON-NLS-1$
						"  END; \n"; //$NON-NLS-1$

				stmt = sqlConnection.prepareStatement(sentence(cmd, null));
				stmt.execute();
				stmt.close();
				// Lo desactivamos
				stmt = sqlConnection
						.prepareStatement(sentence("alter trigger logon_audit_trigger disable",null)); //$NON-NLS-1$
				stmt.execute();
				stmt.close();
				if (debug) log.info("Trigger 'LOGON_AUDIT_TRIGGER' created and disabled", null, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// LOGOFF
			stmtCAC = sqlConnection
					.prepareStatement(sentence("select 1 from user_triggers where UPPER(TRIGGER_NAME) ='LOGOFF_AUDIT_TRIGGER'", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			boolean existeLogoffTriger = rsetCAC.next();

			if (!existeLogoffTriger || actualitzaTriggers) {

				if (existeLogoffTriger && actualitzaTriggers) {
					// Lo desactivamos (para actualizarlo)
					stmt = sqlConnection
							.prepareStatement(sentence("alter trigger LOGOFF_AUDIT_TRIGGER disable", null)); //$NON-NLS-1$
					stmt.execute();
					stmt.close();
					if (debug) log.info("Disabled 'LOGOFF_AUDIT_TRIGGER' to update it", null, null); //$NON-NLS-1$
				}

				// Creamos o reemplazamos el TRIGGER:
				String cmd = "create or replace trigger LOGOFF_AUDIT_TRIGGER before logoff on database \n" + //$NON-NLS-1$
						"  DECLARE \n"
						+ //$NON-NLS-1$
						"    User   varchar2(2048); \n"
						+ //$NON-NLS-1$
						"    IPADDRESS      varchar2(2048); \n"
						+ //$NON-NLS-1$
						"	 programa       VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"  BEGIN \n"
						+ //$NON-NLS-1$
						"    /* NO FEM LOG DE L'User SYS A LOCALHOST */ \n"
						+ //$NON-NLS-1$
						"    --   if (UPPER(User) IN ('SYS') AND IPADDRESS='127.0.0.1') THEN RETURN; END IF;\n"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"    select user into User from DUAL; \n"
						+ //$NON-NLS-1$
						"    /*  si es null, utilizamos el localhost */ \n"
						+ //$NON-NLS-1$
						"    SELECT nvl(SYS_CONTEXT('USERENV','IP_ADDRESS'),'127.0.0.1') \n"
						+ //$NON-NLS-1$
						"      INTO IPADDRESS FROM DUAL; \n"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"    SELECT nvl(module,' ') INTO programa from v$session where audsid = userenv('sessionid') and username is not null and sid=(select SID from v$mystat where rownum=1);"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"    INSERT INTO SC_OR_ACCLOG ( \n"
						+ //$NON-NLS-1$
						"      SAC_USER_ID, \n"
						+ //$NON-NLS-1$
						"      SAC_SESSION_ID, \n"
						+ //$NON-NLS-1$
						"      SAC_PROCESS, \n"
						+ //$NON-NLS-1$
						"      SAC_HOST, \n"
						+ //$NON-NLS-1$
						"      SAC_LOGON_DAY, \n"
						+ //$NON-NLS-1$
						"      SAC_OS_USER, \n"
						+ //$NON-NLS-1$
						"      SAC_PROGRAM \n"
						+ //$NON-NLS-1$
						"    ) \n"
						+ //$NON-NLS-1$
						"    SELECT \n"
						+ //$NON-NLS-1$
						"      User,                             /* user_id */ \n"
						+ //$NON-NLS-1$
						"      Sys_Context('USERENV','SESSIONID'), /* session_id */ \n"
						+ //$NON-NLS-1$
						"      'logoff',                           /* process */ \n"
						+ //$NON-NLS-1$
						"      IPADDRESS,                          /* host */ \n"
						+ //$NON-NLS-1$
						"      sysdate,                            /* LOGON_DAY */ \n"
						+ //$NON-NLS-1$
						"      SYS_CONTEXT('USERENV', 'OS_USER'),  /* OSUSER */ \n"
						+ //$NON-NLS-1$
						"      programa                            /* PROGRAM */ \n"
						+ //$NON-NLS-1$
						"    FROM DUAL; \n" + //$NON-NLS-1$
						"  END; \n"; //$NON-NLS-1$

				stmt = sqlConnection.prepareStatement(sentence(cmd));
				stmt.execute();
				stmt.close();
				// Lo desactivamos
				stmt = sqlConnection
						.prepareStatement(sentence("alter trigger LOGOFF_AUDIT_TRIGGER disable")); //$NON-NLS-1$
				stmt.execute();
				stmt.close();
				if (debug) log.info("Trigger 'LOGOFF_AUDIT_TRIGGER' created and disabled",null, null);
			}
			rsetCAC.close();
			stmtCAC.close();

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.AccessControlVerificationError"), e); //$NON-NLS-1$
		} finally {
			if (rsetCAC != null)
				try {
					rsetCAC.close();
				} catch (Exception e) {
				}
			if (stmtCAC != null)
				try {
					stmtCAC.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}

	}

	private void disableAccessControl()
			throws java.rmi.RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		PreparedStatement stmtCAC = null;
		PreparedStatement stmt = null;
		ResultSet rsetCAC = null;
		try {
			Connection sqlConnection = getConnection();

			// TRIGGERS DE LOGON Y LOGOFF
			// LOGON
			stmtCAC = sqlConnection.prepareStatement(
					sentence("select 1 from user_triggers where upper(TRIGGER_NAME) ='LOGON_AUDIT_TRIGGER'", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			boolean existeLogonTrigger = rsetCAC.next();

			if (existeLogonTrigger) {

				// Lo desactivamos (para actualizarlo)
				stmt = sqlConnection.prepareStatement(sentence("alter trigger logon_audit_trigger disable", null)); //$NON-NLS-1$
				stmt.execute();
				stmt.close();
				if (debug)
					log.info("Disabled 'LOGON_AUDIT_TRIGGER' to updated it", null, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();
			stmtCAC = sqlConnection.prepareStatement(
					sentence("select 1 from user_triggers where upper(TRIGGER_NAME) ='LOGOFF_AUDIT_TRIGGER'", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			existeLogonTrigger = rsetCAC.next();

			if (existeLogonTrigger) {

				// Lo desactivamos (para actualizarlo)
				stmt = sqlConnection.prepareStatement(sentence("alter trigger logoff_audit_trigger disable", null)); //$NON-NLS-1$
				stmt.execute();
				stmt.close();
				if (debug)
					log.info("Disabled 'LOGON_AUDIT_TRIGGER' to updated it", null, null); //$NON-NLS-1$
			}
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(Messages.getString("OracleAgent.AccessControlVerificationError"), e); //$NON-NLS-1$
		} finally {
			if (rsetCAC != null)
				try {
					rsetCAC.close();
				} catch (Exception e) {
				}
			if (stmtCAC != null)
				try {
					stmtCAC.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}

	}

	private String sentence(String cmd) {
		return sentence(cmd, null);
	}

	protected String sentence(String cmd, Password pass) {
		if (debug)
			if (pass == null)
				log.info(cmd);
			else
				log.info(cmd.replace(quotePassword(pass), "******"));
		return cmd;
	}

	/**
	 * Inicializar el agente.
	 */
	public void init() throws InternalErrorException {
		log.info("Starting Oracle agent {}", getSystem().getName(), null); //$NON-NLS-1$
		user = getSystem().getParam0();
		if (getSystem().getParam1() != null) {
			try {
				password = Password.decode(getSystem().getParam1());
			} catch (Exception e) {
				password = null;
			}
		}
		db = getSystem().getParam2();
		rolePassword = getSystem().getParam3() != null ? Password.decode(getSystem().getParam3()) : null;
		debug = "true".equals(getSystem().getParam4());
		defaultProfile = getSystem().getParam5();
		defaultTablespace = getSystem().getParam6();
		temporaryTablespace = getSystem().getParam7();
		if (debug) {
			log.info("user: "+user);
			log.info("password: ********");
			log.info("db: "+db);
			log.info("rolePassword: ********");
			log.info("debug: "+debug);
		}
		// Verifiramos que estén creadas las tablas y los triggers
		try {
			if (Boolean.TRUE.equals( getSystem().getAccessControl()))
			{
				createAccessControl();
				// Obtenim les regles i activem els triggers si correspon
				updateAccessControl();
			} else {
				disableAccessControl();
			}
		} catch (Throwable th) {
			if (debug) log.warn("Error in the access control verification", th); //$NON-NLS-1$
			try {
				// Si hay error desactivamos los triggers (por si acaso)
				setAccessControlActive(false);
			} catch (Throwable tha) {
			}
		}

		getConnection();
		releaseConnection();
	}

	/**
	 * Liberar conexión a la base de datos. Busca en el hash de conexiones
	 * activas alguna con el mismo nombre que el agente y la libera. A
	 * continuación la elimina del hash. Se invoca desde el método de gestión de
	 * errores SQL.
	 */
	public void releaseConnection() {
		Connection conn = (Connection) hash.get(this.getSystem().getName());
		if (conn != null) {
			hash.remove(this.getSystem().getName());
			try {
				conn.close();
			} catch (SQLException e) {
			}
		}
	}

	/**
	 * Obtener una conexión a la base de datos. Si la conexión ya se encuentra
	 * establecida (se halla en el hash de conexiones activas), simplemente se
	 * retorna al método invocante. Si no, registra el driver oracle, efectúa la
	 * conexión con la base de datos y la registra en el hash de conexiones
	 * activas
	 * 
	 * @return conexión SQL asociada.
	 * @throws InternalErrorException
	 *             algún error en el proceso de conexión
	 */
	boolean disableSysdba = false;
	private Collection<ExtensibleObjectMapping> objectMappings;
	private ObjectTranslator objectTranslator;
	public Connection getConnection() throws InternalErrorException {
		Connection conn = (Connection) hash.get(this.getSystem().getName());
		if (conn == null) {
			try {
				DriverManager
						.registerDriver(new oracle.jdbc.driver.OracleDriver());
				// Connect to the database
				try {
					Properties props = new Properties();
					props.put("user", user); //$NON-NLS-1$
					props.put("password", password.getPassword()); //$NON-NLS-1$
					if (!disableSysdba)
						props.put("internal_logon", "sysdba"); //$NON-NLS-1$ //$NON-NLS-2$
					conn = DriverManager.getConnection(db, props);
					log.info("Connected as sysdba");
				} catch (SQLException e) {
//					log.info("Cannot connect as sysdba");
					conn = DriverManager.getConnection(db, user,
							password.getPassword());
					disableSysdba = true;
				}
				hash.put(this.getSystem().getName(), conn);
				Statement stmt = conn.createStatement();
				stmt.executeQuery("set role all");
				stmt.close();
			} catch (SQLException e) {
				log.info("Error connecting to the database",e);
				throw new InternalErrorException(
						Messages.getString("OracleAgent.ConnectionError"), e); //$NON-NLS-1$
			}
		}
		return conn;
	}

	/**
	 * Gestionar errores SQL. Debe incovarse cuando se produce un error SQL. Si
	 * el sistema lo considera oportuno cerrará la conexión SQL.
	 * 
	 * @param e
	 *            Excepción oralce producida
	 * @throws InternalErrorExcepción
	 *             error que se debe propagar al servidor (si es neceasario)
	 */
	public void handleSQLException(SQLException e)
			throws InternalErrorException {
		if (debug) log.warn(this.getSystem().getName() + " SQL Exception: ", e); //$NON-NLS-1$
		if (e.getMessage().indexOf("Broken pipe") > 0) { //$NON-NLS-1$
			releaseConnection();
		}
		else if (e.getMessage().indexOf("Invalid Packet") > 0) { //$NON-NLS-1$
			releaseConnection();
		}
		else if (e.toString().indexOf("ORA-01000") > 0) { //$NON-NLS-1$
			releaseConnection();
		}
		else if (e.toString().indexOf("ORA-01012") > 0) { //$NON-NLS-1$
			releaseConnection();
		}
		else if (e.toString().indexOf("ORA-02396") > 0) { //$NON-NLS-1$ Timeout
			releaseConnection();
		}
		else if (e.toString().indexOf("Closed Connection") > 0) { //$NON-NLS-1$
			releaseConnection();
		}
		if (e.toString().indexOf("Malformed SQL92") > 0) { //$NON-NLS-1$
			e.printStackTrace(System.out);
			return;
		}
		e.printStackTrace(System.out);
		throw new InternalErrorException("Error ejecutando sentencia SQL", e);
	}

	/**
	 * Actualizar los datos del usuario. Crea el usuario en la base de datos y
	 * le asigna una contraseña aleatoria. <BR>
	 * Da de alta los roles<BR>
	 * Le asigna los roles oportuno.<BR>
	 * Le retira los no necesarios.
	 * 
	 * @param user
	 *            código de usuario
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUser(Account account, User usu)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		String user = account.getName();
		// boolean active;
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;
		// String groupsConcat = "";
		Collection<RoleGrant> roles;
		Collection<Group> groups;

		String groupsAndRoles[];
		int i;

		// Control de acceso (tabla de roles)
		boolean cacActivo = false; // indica si está activo el control de acceso
		PreparedStatement stmtCAC = null;
		ResultSet rsetCAC = null;

		try {
			// Obtener los datos del usuario
			roles = getServer().getAccountRoles(user,
					this.getSystem().getName());

			groups = null;
			groupsAndRoles = concatUserGroupsAndRoles(groups, roles);

			Connection sqlConnection = getConnection();

			// Comprobar si el usuario existe
			stmt = sqlConnection
					.prepareStatement(sentence("SELECT 1 FROM SYS.DBA_USERS WHERE USERNAME=?")); //$NON-NLS-1$
			stmt.setString(1, user.toUpperCase());
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			final boolean newObject = !rset.next();
			if (newObject) {
				stmt.close();

				Password pass = getServer().getOrGenerateUserPassword(user,
						getSystem().getName());

				String cmd = "CREATE USER \"" + user.toUpperCase() + "\" IDENTIFIED BY \"" + //$NON-NLS-1$ //$NON-NLS-2$
						quotePassword(pass) + "\"";
				if (defaultProfile != null && !defaultProfile.trim().isEmpty())
					cmd += " PROFILE " + defaultProfile;
				if (temporaryTablespace != null && !temporaryTablespace.trim().isEmpty())
					cmd += " TEMPORARY TABLESPACE " + temporaryTablespace;
				if (defaultTablespace != null && !defaultTablespace.trim().isEmpty())
					cmd += " DEFAULT TABLESPACE " + defaultTablespace;
				cmd += " ACCOUNT UNLOCK ";
				
				if (! runTriggers(SoffidObjectType.OBJECT_USER, SoffidObjectTrigger.PRE_INSERT, new UserExtensibleObject(account, usu, getServer()))) {
					if (debug)
						log.info("Ignoring creation of user "+account.getName()+" due to pre-insert trigger failure");
					return;
				}
				stmt = sqlConnection.prepareStatement(sentence(cmd, pass));
				stmt.execute();
			} else {
				if (! runTriggers(SoffidObjectType.OBJECT_USER, SoffidObjectTrigger.PRE_UPDATE, new UserExtensibleObject(account, usu, getServer()))) {
					if (debug)
						log.info("Ignoring creation of user "+account.getName()+" due to pre-insert trigger failure");
					return;
				}
				
			}
			// System.out.println ("Usuario "+user+" ya existe");
			rset.close();
			stmt.close();
			// passada a removeUser()
			stmt = sqlConnection
					.prepareStatement(sentence("GRANT CREATE SESSION TO  \"" + user.toUpperCase() + "\"", null)); //$NON-NLS-1$ //$NON-NLS-2$
			stmt.execute();
			stmt.close();

			stmt = sqlConnection
					.prepareStatement(sentence("ALTER USER \"" + user.toUpperCase() + "\" ACCOUNT UNLOCK")); //$NON-NLS-1$ //$NON-NLS-2$
			stmt.execute();
			stmt.close();

			// Eliminar los roles que sobran
			stmt = sqlConnection
					.prepareStatement(sentence("SELECT GRANTED_ROLE FROM SYS.DBA_ROLE_PRIVS WHERE GRANTEE=?")); //$NON-NLS-1$
			stmt.setString(1, user.toUpperCase());
			rset = stmt.executeQuery();
			stmt2 = sqlConnection.prepareStatement("select 1 from dual"); //no s'admet constructor buit //$NON-NLS-1$
			while (rset.next()) {
				boolean found = false;
				String role = rset.getString(1);
				for (i = 0; groupsAndRoles != null && !found
						&& i < groupsAndRoles.length; i++) {
					if (groupsAndRoles[i] != null
							&& groupsAndRoles[i].equalsIgnoreCase(role)) {
						found = true;
						groupsAndRoles[i] = null;
					}
				}
				if (!found) {
					RoleGrant r = new RoleGrant();
					r.setRoleName(role);
					r.setSystem(getAgentName());
					r.setOwnerAccountName(account.getName());
					r.setOwnerSystem(account.getSystem());
					if ( runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer()))) 
					{
						stmt2.execute("REVOKE \"" + role + "\" FROM \"" + user.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						boolean ok = runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())); 
					} else {
						if (debug)
							log.info("Grant not revoked due to pre-delete trigger failure");
					}

				}
			}
			rset.close();
			stmt.close();

			String rolesPorDefecto = null;

			// Crear los roles si son necesarios
			for (RoleGrant r : roles) {
				if (r != null) {
					// if(r.){
					if (rolesPorDefecto == null)
						rolesPorDefecto = "\"" + r.getRoleName().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
					else
						rolesPorDefecto = rolesPorDefecto + ",\"" + //$NON-NLS-1$
								r.getRoleName().toUpperCase() + "\""; //$NON-NLS-1$
					// }
					stmt = sqlConnection
							.prepareStatement(sentence("SELECT 1 FROM SYS.DBA_ROLES WHERE ROLE=?")); //$NON-NLS-1$
					stmt.setString(1, r.getRoleName().toUpperCase());
					rset = stmt.executeQuery();
					if (!rset.next()) {
						Role role = getServer().getRoleInfo(r.getRoleName(), getAgentName());
						if ( runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.PRE_INSERT, new com.soffid.iam.sync.engine.extobj.RoleExtensibleObject(role, getServer())) ) 
						{
							// Password protected or not
							String command = "CREATE ROLE \"" + r.getRoleName().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
							if (getServer().getRoleInfo(r.getRoleName(),
									r.getSystem()).getPassword())
								command = command + " IDENTIFIED BY \"" + //$NON-NLS-1$
										rolePassword.getPassword().replaceAll("\"", PASSWORD_QUOTE_REPLACEMENT) + "\""; //$NON-NLS-1$
							stmt2.execute(command);
							// Revoke de mi mismo
							stmt2.execute("REVOKE \"" + r.getRoleName().toUpperCase() + "\" FROM \"" + this.user.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
							runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.POST_INSERT, new com.soffid.iam.sync.engine.extobj.RoleExtensibleObject(role, getServer()));
						} else {
							if (debug)
								log.info("Grant not executed due to pre-insert trigger failure");
						}
					}
					rset.close();
					stmt.close();
				}
			}

			// Añadir los roles que no tiene
			for (i = 0; /* active && */groupsAndRoles != null
					&& i < groupsAndRoles.length; i++) {
				if (groupsAndRoles[i] != null) {
					RoleGrant r = new RoleGrant();
					r.setRoleName(groupsAndRoles[i]);
					r.setSystem(getAgentName());
					r.setOwnerAccountName(account.getName());
					r.setOwnerSystem(account.getSystem());
					if ( runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer()))) 
					{
						stmt2.execute("GRANT \"" + groupsAndRoles[i].toUpperCase() + "\" TO  \"" + user.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						boolean ok = runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())); 
					} else {
						if (debug)
							log.info("Grant not executed due to pre-insert trigger failure");
					}
				}
			}

			// Ajustar los roles por defecto
			if (rolesPorDefecto == null)
				rolesPorDefecto = "NONE"; //$NON-NLS-1$
			String ss = "ALTER USER \"" + user.toUpperCase() + "\" DEFAULT ROLE " + //$NON-NLS-1$ //$NON-NLS-2$
					rolesPorDefecto;
			// System.out.println (ss);
			stmt2.execute(ss);

			runTriggers(SoffidObjectType.OBJECT_USER, newObject ? SoffidObjectTrigger.POST_INSERT : SoffidObjectTrigger.POST_UPDATE, new UserExtensibleObject(account, usu, getServer()));


			// Insertamos en la tabla de roles para CONTROL DE ACCESO (¿solo si
			// el usuario está activo??)
			if (Boolean.TRUE.equals( getSystem().getAccessControl()))
			{
				String[] grupsAndRolesCAC = concatUserGroupsAndRoles(groups,
						roles);
				HashSet grupsAndRolesHash = (grupsAndRolesCAC != null && grupsAndRolesCAC.length != 0) ? new HashSet(
						Arrays.asList(grupsAndRolesCAC)) // eliminem repetits
						: new HashSet(); // evitem error al ésser llista buida
				grupsAndRolesCAC = (String[]) grupsAndRolesHash
						.toArray(new String[0]);
				// 1) Obtenemos los roles que ya tiene
				stmt = sqlConnection
						.prepareStatement(sentence("SELECT SOR_GRANTED_ROLE FROM SC_OR_ROLE WHERE SOR_GRANTEE=?")); //$NON-NLS-1$
				stmt.setString(1, user.toUpperCase());
				rset = stmt.executeQuery();
				stmt2 = sqlConnection.prepareStatement("select 1 from dual"); //$NON-NLS-1$
				while (rset.next()) {
					boolean found = false;
					String role = rset.getString(1);
					for (i = 0; grupsAndRolesCAC != null && !found
							&& i < grupsAndRolesCAC.length; i++) {
						if (grupsAndRolesCAC[i] != null
								&& grupsAndRolesCAC[i].equalsIgnoreCase(role)) {
							found = true;
							grupsAndRolesCAC[i] = null;
						}
					}
					if (/* !active || */!found) {
						stmt2.execute("DELETE FROM SC_OR_ROLE WHERE SOR_GRANTEE='" //$NON-NLS-1$
								+ user.toUpperCase()
								+ "' AND SOR_GRANTED_ROLE ='" //$NON-NLS-1$
								+ role.toUpperCase() + "'"); //$NON-NLS-1$
						stmt2.close();
					}

				}
				rset.close();
				stmt.close();
				// Añadir los roles que no tiene
				if (/* active && */grupsAndRolesCAC != null)
					for (i = 0; i < grupsAndRolesCAC.length; i++) {
						if (grupsAndRolesCAC[i] != null) {
							stmt2 = sqlConnection
									.prepareStatement(sentence("INSERT INTO SC_OR_ROLE (SOR_GRANTEE, SOR_GRANTED_ROLE) SELECT '" //$NON-NLS-1$
											+ user.toUpperCase()
											+ "', '" + grupsAndRolesCAC[i].toUpperCase() + "' FROM DUAL ")); //$NON-NLS-1$ //$NON-NLS-2$
							stmt2.execute();
							stmt2.close();
						}
					}

			}// FIN_CAC_ACTIVO

			if (false /* hack for Idealista */ ) {
				// Unlock account
				Password p = getServer().getAccountPassword(account.getName(), getAgentName());
				if (p != null) {
					String cmd = "ALTER USER \"" + user.toUpperCase() + "\" IDENTIFIED BY \"" + //$NON-NLS-1$ //$NON-NLS-2$
							quotePassword(p) + "\" ACCOUNT UNLOCK"; //$NON-NLS-1$
					stmt2 = sqlConnection
							.prepareStatement(sentence(cmd, p)); //$NON-NLS-1$ //$NON-NLS-2$
					stmt2.execute();
					stmt2.close();
					
				}
				
			}
			
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ProcessingTaskError"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
	}

	protected String quotePassword(Password pass) {
		return pass.getPassword().replaceAll("\"", PASSWORD_QUOTE_REPLACEMENT);
	}

	/**
	 * Actualizar la contraseña del usuario. Asigna la contraseña si el usuario
	 * está activo y la contraseña no es temporal. En caso de contraseñas
	 * temporales, asigna un contraseña aleatoria.
	 * 
	 * @param user
	 *            código de usuario
	 * @param password
	 *            contraseña a asignar
	 * @param mustchange
	 *            es una contraseña temporal?
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUserPassword(String user, User arg1, Password password,
			boolean mustchange)
			throws es.caib.seycon.ng.exception.InternalErrorException {
		if (debug) log.info("updateUserPassword");
		PreparedStatement stmt = null;
		String cmd = ""; //$NON-NLS-1$
		try {
			Account acc = getServer().getAccountInfo(user, getAgentName());
			// Comprobar si el usuario existe
			Connection sqlConnection = getConnection();
			stmt = sqlConnection
					.prepareStatement(sentence("SELECT USERNAME FROM SYS.DBA_USERS " + //$NON-NLS-1$
							"WHERE USERNAME='" + user.toUpperCase() + "'")); //$NON-NLS-1$ //$NON-NLS-2$
			ResultSet rset = stmt.executeQuery();
			if (rset.next() && password.getPassword().length() > 0) {
				stmt.close();
				if (arg1 == null) {
					if (! runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.PRE_UPDATE, new AccountExtensibleObject(acc, getServer()))) 
						return;
				}
				else {
					if (! runTriggers(SoffidObjectType.OBJECT_USER, SoffidObjectTrigger.PRE_UPDATE, new UserExtensibleObject(acc, arg1, getServer()))) 
						return;
				}
					
				cmd = "ALTER USER \"" + user.toUpperCase() + "\" IDENTIFIED BY \"" + //$NON-NLS-1$ //$NON-NLS-2$
						quotePassword(password) + "\" ACCOUNT UNLOCK"; //$NON-NLS-1$
				if (mustchange)
					cmd = cmd + " PASSWORD EXPIRE";
				stmt = sqlConnection.prepareStatement(sentence(cmd, password));
				stmt.execute();
				if (arg1 == null) {
					if (! runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.POST_UPDATE, new AccountExtensibleObject(acc, getServer()))) 
						return;
				}
				else {
					if (! runTriggers(SoffidObjectType.OBJECT_USER, SoffidObjectTrigger.POST_UPDATE, new UserExtensibleObject(acc, arg1, getServer()))) 
						return;
				}
			}
		} catch (SQLException e) {
			handleSQLException(e);
		}/*
		 * catch (UnknownUserException e) { if (stmt!=null) try {stmt.close();}
		 * catch (Exception e2) {} }
		 */catch (Exception e) {
			e.printStackTrace();
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e2) {
				}
			throw new InternalErrorException(
					Messages.getString("OracleAgent.UpdatingPasswordError"), e); //$NON-NLS-1$
		} finally {
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}
	}

	/**
	 * Validar contraseña.
	 * 
	 * @param user
	 *            código de usuario
	 * @param password
	 *            contraseña a asignar
	 * @return false
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public boolean validateUserPassword(String user, Password password)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try {
			Properties props = new Properties();
			props.put("user", user); //$NON-NLS-1$
			props.put("password", password.getPassword()); //$NON-NLS-1$
			Connection conn = DriverManager.getConnection(db, props);
			conn.close();
			return true;
		} catch (SQLException e) {
			log.info("Error validating password for "+user+": "+e.getMessage());
		}
		return false;
	}

	/**
	 * Concatenar los vectores de grupos y roles en uno solo. Si el agente está
	 * basado en roles y no tiene ninguno, retorna el valor null
	 * 
	 * @param groups
	 *            vector de grupos
	 * @param roles
	 *            vector de roles
	 * @return vector con nombres de grupo y role
	 */
	public String[] concatUserGroupsAndRoles(Collection<Group> groups,
			Collection<RoleGrant> roles) {
		int i;
		int j;

		if (roles.isEmpty() && getSystem().getRolebased()) // roles.length == 0
															// && getRoleBased
															// ()
			return null;
		LinkedList<String> concat = new LinkedList<String>();
		if (groups != null) {
			for (Group g : groups)
				concat.add(g.getName());
		}
		for (RoleGrant rg : roles) {
			concat.add(rg.getRoleName());
		}

		return concat.toArray(new String[concat.size()]);
	}

	public String[] concatRoleNames(Collection<RoleGrant> roles) {
		if (roles.isEmpty() && getSystem().getRolebased())
			return null;

		LinkedList<String> concat = new LinkedList<String>();
		for (RoleGrant rg : roles) {
			concat.add(rg.getRoleName());
		}

		return concat.toArray(new String[concat.size()]);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see es.caib.seycon.RoleMgr#UpdateRole(java.lang.String,
	 * java.lang.String)
	 */
	public void updateRole(Role ri) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		String bd = ri.getSystem();
		String role = ri.getName();
		PreparedStatement stmt = null;
		String cmd = ""; //$NON-NLS-1$
		try {
			if (this.getSystem().getName().equals(bd)) {
				// Comprobar si el rol existe en la bd
				Connection sqlConnection = getConnection();
				stmt = sqlConnection
						.prepareStatement(sentence("SELECT ROLE FROM SYS.DBA_ROLES " + //$NON-NLS-1$
								"WHERE ROLE='" + role.toUpperCase() + "'")); //$NON-NLS-1$ //$NON-NLS-2$
				ResultSet rset = stmt.executeQuery();
				if (!rset.next()) // aquest rol NO existeix com a rol de la BBDD
				{
					if (ri != null) {// si el rol encara existeix al seycon (no
										// s'ha esborrat)
						if ( runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.PRE_INSERT, new RoleExtensibleObject(ri, getServer())) )  {
							stmt.close();
							cmd = "CREATE ROLE \"" + role.toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
	
							if (ri.getPassword()) {
								cmd = cmd+ " IDENTIFIED BY \"" +  quotePassword(rolePassword) + "\""; //$NON-NLS-1$ //$NON-NLS-2$
							}
							stmt = sqlConnection.prepareStatement(sentence(cmd, rolePassword));
							stmt.execute();
							// Fem un revoke per a l'User SYSTEM (CAI-579530:
							// u88683)
							stmt.close();
							stmt = sqlConnection
									.prepareStatement(sentence("REVOKE \"" + role.toUpperCase() + "\" FROM \"" + user.toUpperCase() + "\"")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
							stmt.execute();
	
							runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.POST_INSERT, new RoleExtensibleObject(ri, getServer())) ;
						} else {
							if (debug)
								log.info("Creation of role "+ri.getName()+" ignored due to pre-insert trigger failure");
						}
					}
				}
				if (Boolean.TRUE.equals( getSystem().getAccessControl()))
				{
					if (ri != null ) {
						// Afegim informació dels usuaris que actualment tenen
						// atorgat el rol a la bbdd (la info no és completa
						// però és consistent amb el rol de bbdd)
						// Ara inserim en SC_OR_ORACLE els usuaris q tinguen el
						// rol a la base de dades
						String cmdrole = "INSERT INTO SC_OR_ROLE(SOR_GRANTEE, SOR_GRANTED_ROLE) " //$NON-NLS-1$
								+ "SELECT GRANTEE, GRANTED_ROLE FROM SYS.DBA_ROLE_PRIVS WHERE GRANTED_ROLE= '" + role.toUpperCase() + "' MINUS " //$NON-NLS-1$ //$NON-NLS-2$
								+ "SELECT SOR_GRANTEE, sor_granted_role FROM SC_OR_ROLE WHERE sor_granted_role='" + role.toUpperCase() + "'"; //$NON-NLS-1$ //$NON-NLS-2$
						stmt = sqlConnection.prepareStatement(sentence(cmdrole));
						stmt.execute();
						stmt.close();
					}
				}
				stmt.close();
				rset.close();
			}
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e2) {
				}
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingRole"), e); //$NON-NLS-1$
		}
	}

	private void setAccessControlActive(boolean active)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		PreparedStatement stmtCAC = null;
		PreparedStatement stmt = null;
		ResultSet rsetCAC = null;
		try {
			Connection sqlConnection = getConnection();
			// Activamos los triggers de logon y de loggoff
			String estado = active ? "ENABLE" : "DISABLE"; //$NON-NLS-1$ //$NON-NLS-2$
			if (debug) log.info("Activated access control " + active, null, null); //$NON-NLS-1$

			// LOGON
			stmtCAC = sqlConnection
					.prepareStatement(sentence("select 1 from user_triggers where upper(TRIGGER_NAME) ='LOGON_AUDIT_TRIGGER'")); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (rsetCAC.next()) {
				String cmd = "alter trigger LOGON_AUDIT_TRIGGER " + estado; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(sentence(cmd));
				stmt.execute();
				stmt.close();
				if (debug) log.info("Establish 'LOGON_AUDIT_TRIGGER' as " + estado, null, null); //$NON-NLS-1$
			} else {
				if (debug) log.warn("The trigger 'LOGON_AUDIT_TRIGGER' does not exists"); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			stmtCAC = sqlConnection
					.prepareStatement(sentence("select 1 from user_triggers where upper(TRIGGER_NAME) ='LOGOFF_AUDIT_TRIGGER'")); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (rsetCAC.next()) {
				String cmd = "alter trigger LOGOFF_AUDIT_TRIGGER " + estado; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(sentence(cmd));
				stmt.execute();
				stmt.close();
				if (debug) log.info("Establish 'LOGOFF_AUDIT_TRIGGER' as" + estado, null, null); //$NON-NLS-1$
			} else {
				if (debug) log.warn("The trigger 'LOGOFF_AUDIT_TRIGGER' does not exists"); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.281"), e); //$NON-NLS-1$
		} finally {
			if (rsetCAC != null)
				try {
					rsetCAC.close();
				} catch (Exception e) {
				}
			if (stmtCAC != null)
				try {
					stmtCAC.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}
	}

	/**
	 * Nos permite comparar si una regla de control de acceso ya existe
	 * 
	 * @param cac
	 * @param s_user
	 * @param s_role
	 * @param s_host
	 * @param s_program
	 * @param s_cac_id
	 * @return
	 */
	private boolean equalsControlAccess(AccessControl cac, String s_user,
			String s_role, String s_host, String s_program, String s_cac_id) {

		// Si no es la misma fila, no continuamos (AÑADIDO POR TRAZAS)
		if (!s_cac_id.equals(cac.getId()))
			return false; // idControlAcces canviat per getId

		// User o rol ha de ser nulo (uno de los dos)
		if (s_user == null) {
			if (cac.getGenericUser() != null)
				return false;
		} else {
			if (!s_user.equals(cac.getGenericUser()))
				return false;
		}
		if (s_role == null) {
			if (cac.getRoleDescription() != null)
				return false;
		} else {
			if (!s_role.equals(cac.getRoleDescription()))
				return false;
		}
		if (s_host == null) {
			if (cac.getHostId() != null)
				return false;
		} else {
			if (!s_host.equals(cac.getHostId()))
				return false;
		}
		if (s_program == null) {
			if (cac.getProgram() != null)
				return false;
		} else {
			if (!s_program.equals(cac.getProgram()))
				return false;
		}

		return true; // Ha pasat totes les comprovacions

	}

	public void updateAccessControl() throws RemoteException,
			InternalErrorException {
		SystemAccessControl dispatcherInfo = null; // Afegit AccessControl
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		try {
			dispatcherInfo = getServer().getDispatcherAccessControl(
					this.getSystem().getId());
			// dispatcherInfo =
			// getServer().getSystemInfo(this.getSystem().getName());
			Connection sqlConnection = getConnection();

			if (dispatcherInfo == null) {
				setAccessControlActive(false); // desactivamos triggers
				throw new Exception(Messages.getString("OracleAgent.282") //$NON-NLS-1$
						+ this.getSystem().getName()
						+ Messages.getString("OracleAgent.283")); //$NON-NLS-1$
			}

			if (dispatcherInfo.getEnabled()) { // getControlAccessActiu()
				// Lo activamos al final (!!)

				// Obtenemos las reglas de control de acceso
				List<AccessControl> controlAcces = dispatcherInfo.getControlAcces();
				// ArrayList<ControlAccess> controlAccess =
				// dispatcherInfo.getControlAcces();

				if (controlAcces == null || controlAcces.size() == 0) {
					// Eliminem les regles de control d'accés
					String cmd = "DELETE FROM SC_OR_CONACC"; //$NON-NLS-1$
					stmt = sqlConnection.prepareStatement(sentence(cmd));
					stmt.execute(cmd);
					stmt.close();
				} else {
					stmt = sqlConnection
							.prepareStatement(sentence("SELECT SOC_USER,SOC_ROLE,SOC_HOST,SOC_PROGRAM, SOC_CAC_ID from SC_OR_CONACC")); //$NON-NLS-1$
					rset = stmt.executeQuery();

					while (rset.next()) {
						boolean found = false;
						String s_user = rset.getString(1);
						String s_role = rset.getString(2);
						String s_host = rset.getString(3);
						String s_program = rset.getString(4);
						String s_idcac = rset.getString(5); // por id
															// ¿necesario?

						for (int i = 0; /* !found && */i < controlAcces.size(); i++) {
							AccessControl cac = controlAcces.get(i);
							if (cac != null
									&& equalsControlAccess(cac, s_user, s_role,
											s_host, s_program, s_idcac)) {
								found = true; // ya existe: no lo creamos
								controlAcces.set(i, null);
							}
						}

						if (!found) {// No l'hem trobat: l'esborrem
							String condicions = ""; //$NON-NLS-1$
							// SOC_USER,SOC_ROLE,SOC_HOST,SOC_PROGRAM
							if (s_user == null)
								condicions += " AND SOC_USER is null "; //$NON-NLS-1$
							else
								condicions += " AND SOC_USER=? "; //$NON-NLS-1$
							if (s_role == null)
								condicions += " AND SOC_ROLE is null "; //$NON-NLS-1$
							else
								condicions += " AND SOC_ROLE=? "; //$NON-NLS-1$
							stmt2 = sqlConnection
									.prepareStatement(sentence("DELETE SC_OR_CONACC WHERE SOC_HOST=? AND SOC_PROGRAM=? " //$NON-NLS-1$
											+ condicions));
							stmt2.setString(1, s_host);
							stmt2.setString(2, s_program);
							int pos = 3;
							if (s_user != null)
								stmt2.setString(pos++, s_user);
							if (s_role != null)
								stmt2.setString(pos++, s_role);
							stmt2.execute();
							stmt2.close();
						}
					}
					rset.close();
					stmt.close();
					// añadimos los que no tiene
					for (int i = 0; i < controlAcces.size(); i++) {
						if (controlAcces.get(i) != null) {
							AccessControl cac = controlAcces.get(i);
							stmt2 = sqlConnection
									.prepareStatement(sentence("INSERT INTO SC_OR_CONACC(SOC_USER, SOC_ROLE, SOC_HOST, SOC_PROGRAM, SOC_CAC_ID, SOC_HOSTNAME) VALUES (?,?,?,?,?,?)")); //$NON-NLS-1$
							stmt2.setString(1, cac.getGenericUser());
							stmt2.setString(2, cac.getRoleDescription());
							stmt2.setString(3, cac.getRemoteIp());
							stmt2.setString(4, cac.getProgram());
							stmt2.setString(5, cac.getId().toString());
							stmt2.setString(6, cac.getHostName());
							stmt2.execute();
							stmt2.close();
						}
					}
				}
				// Los activamos tras propagar las reglas (!!)
				setAccessControlActive(true); // Activamos triggers

			} else { // Desactivamos los triggers
				setAccessControlActive(false);
			}
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.293"), e); //$NON-NLS-1$
		} finally { // tamquem
			if (rset != null) {
				try {
					rset.close();
				} catch (Exception e) {
				}
			}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e2) {
				}
			if (stmt2 != null) {
				try {
					stmt2.close();
				} catch (Exception e) {
				}
			}
		}
	}

	public Collection<? extends LogEntry> getLogFromDate(Date From)
			throws RemoteException, InternalErrorException {
		SystemAccessControl dispatcherInfo = getServer().getDispatcherAccessControl(
				this.getSystem().getId());
		if ( !  dispatcherInfo.getEnabled())
			return null;
		PreparedStatement stmt = null;
		ResultSet rset = null;
		// ArrayList<LogEntry> logs = new ArrayList<LogEntry>();
		Collection<LogEntry> logs = null;
		try {
			Connection sqlConnection = getConnection();
			// Obtenemos los logs
			String consulta = "select SAC_USER_ID, SAC_SESSION_ID, SAC_PROCESS, SAC_HOST, " //$NON-NLS-1$
					+ "SAC_LOGON_DAY, SAC_OS_USER, SAC_PROGRAM from SC_OR_ACCLOG "; //$NON-NLS-1$

			if (From != null)
				consulta += "WHERE SAC_LOGON_DAY>=? "; //$NON-NLS-1$
			consulta += " order by SAC_LOGON_DAY "; //$NON-NLS-1$
			if (debug) log.info("consulta: "+consulta);
			stmt = sqlConnection.prepareStatement(sentence(consulta));

			if (From != null)
				stmt.setTimestamp(1, new java.sql.Timestamp(From.getTime()));
			rset = stmt.executeQuery();
			String cadenaConnexio = db;
			int posArroba = cadenaConnexio.indexOf("@"); //$NON-NLS-1$
			int posDosPunts = cadenaConnexio.indexOf(":", posArroba); //$NON-NLS-1$
			String hostDB = null;
			if (posArroba != -1 && posDosPunts != -1)
				hostDB = cadenaConnexio.substring(posArroba + 1, posDosPunts); // nombre
																				// del
																				// servidor
			if (hostDB == null || "localhost".equalsIgnoreCase(hostDB)) //$NON-NLS-1$
				hostDB = InetAddress.getLocalHost().getCanonicalHostName();
			while (rset.next() && logs.size() <= 100) { // Limitem per 100 file
				LogEntry log = new LogEntry();
				log.setHost(hostDB);
				log.setProtocol("OTHER"); // De la tabla de serveis //$NON-NLS-1$

				// Usuario S.O.
				log.setUser(rset.getString(6));
				log.SessionId = rset.getString(2);
				log.info = "dbUser: " + rset.getString(1) + " Program: " + rset.getString(7); //7 = program //$NON-NLS-1$ //$NON-NLS-2$
				String proceso = rset.getString(3);
				if ("logon".equalsIgnoreCase(proceso)) //$NON-NLS-1$
					log.type = LogEntry.LOGON;
				else if ("logoff".equalsIgnoreCase(proceso)) //$NON-NLS-1$
					log.type = LogEntry.LOGOFF;
				else if ("not-allowed".equalsIgnoreCase(proceso)) { //$NON-NLS-1$
					log.type = LogEntry.LOGON_DENIED;
					log.info += " LOGON DENIED (Access control)"; //$NON-NLS-1$
				} else
					log.type = -1; // desconocido
				log.setClient(rset.getString(4));
				log.setDate(rset.getTimestamp(5));

				logs.add(log);
			}
			rset.close();
			stmt.close();
			return logs; // .toArray(new LogEntry[0]);
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.308"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}

		return null;
	}

	public void removeRole(String nom, String bbdd) {
		try {
			Connection sqlConnection = getConnection();
			if (this.getSystem().getName().equals(bbdd)) {
				Role ri = new Role();
				ri.setName(nom);
				ri.setSystem(bbdd);
				PreparedStatement stmtCAC = null;
				if ( runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.PRE_DELETE, new RoleExtensibleObject(ri, getServer())) )  {
					stmtCAC = sqlConnection
							.prepareStatement(sentence("DROP ROLE \"" + nom.toUpperCase() + "\"")); //$NON-NLS-1$ //$NON-NLS-2$
					stmtCAC.execute();
					stmtCAC.close();
					runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.POST_DELETE, new RoleExtensibleObject(ri, getServer()));
				} else {
					if (debug)
						log.info("Removal of role "+nom+" has been ignored due to pre-delete trigger failure");
				}
				// Borramos las filas de control de acceso relacionadas
				// con el ROL

				ResultSet rsetCAC = null;
				try {
					stmtCAC = sqlConnection
							.prepareStatement(sentence("select 1 from user_tables where table_name ='SC_OR_ROLE'")); //$NON-NLS-1$
					rsetCAC = stmtCAC.executeQuery();

					if (rsetCAC.next()) { // Borramos referencias al rol en la
											// tabla SC_OR_ROLE
						stmtCAC.close();
						stmtCAC = sqlConnection
								.prepareStatement(sentence("DELETE FROM SC_OR_ROLE WHERE SOR_GRANTED_ROLE='" + nom.toUpperCase() + "'")); //$NON-NLS-1$ //$NON-NLS-2$
						stmtCAC.execute();
						stmtCAC.close();
					}
				} finally {
					try {
						rsetCAC.close();
					} catch (Exception ex) {
					}
					try {
						stmtCAC.close();
					} catch (Exception ex) {
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public void removeUser(String arg0) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		if (debug) log.info("removeUser");
		try {
			Account account = getServer().getAccountInfo(arg0, getAgentName());
			if (account == null || account.getStatus() == AccountStatus.REMOVED)
			{
				// Comprobar si el usuario existe
				Connection sqlConnection = getConnection();
				PreparedStatement stmt = null;
				stmt = sqlConnection
						.prepareStatement(sentence("SELECT 1 FROM SYS.DBA_USERS WHERE USERNAME=?")); //$NON-NLS-1$
				stmt.setString(1, arg0.toUpperCase());
				ResultSet rset = stmt.executeQuery();
				// Determinar si el usuario está o no activo
				// Si no existe darlo de alta
				if (rset.next()) {
					if (account == null) {
						account = new Account();
						account.setName(arg0);
						account.setSystem(getAgentName());
					}
					if ( runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.PRE_DELETE, new AccountExtensibleObject(account, getServer())) )  {
						rset.close();
						stmt.close();
						if (debug) log.info("Dropping user "+arg0);
						stmt = sqlConnection
								.prepareStatement(sentence("DROP USER \"" + arg0.toUpperCase() + "\"")); //$NON-NLS-1$ //$NON-NLS-2$
						try {
							stmt.execute();
						} catch (SQLException e) {
							handleSQLException(e);
						} finally {
							stmt.close();
						}
						runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.POST_DELETE, new AccountExtensibleObject(account, getServer()));
					} else {
						if (debug)
							log.info("Removal of account "+arg0+" has been ignored due to pre-delete trigger failure");
					}
				}
				else
					stmt.close();
			}
			else
			{
				if ( runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.PRE_UPDATE, new AccountExtensibleObject(account, getServer())) )  {
					Connection sqlConnection = getConnection();
					PreparedStatement stmt = null;
					stmt = sqlConnection
							.prepareStatement(sentence("REVOKE CREATE SESSION FROM \"" + arg0.toUpperCase() + "\"")); //$NON-NLS-1$ //$NON-NLS-2$
					try {
						stmt.execute();
					} catch (SQLException e) {
						if (e.getErrorCode() != -1952 && !e.getMessage().contains("ORA-01952"))
							handleSQLException(e);
					} finally {
						stmt.close();
					}
					stmt = sqlConnection
							.prepareStatement(sentence("ALTER USER \"" + arg0.toUpperCase() + "\" ACCOUNT LOCK")); //$NON-NLS-1$ //$NON-NLS-2$
					stmt.execute();
					stmt.close();
	
					// Borramos las referencias de la tabla de control de acceso
					if (Boolean.TRUE.equals( getSystem().getAccessControl())) {
						stmt = sqlConnection
								.prepareStatement(sentence("DELETE FROM SC_OR_ROLE WHERE SOR_GRANTEE='" //$NON-NLS-1$
										+ arg0.toUpperCase() + "'")); //$NON-NLS-1$
						try {
							stmt.execute();
						} catch (SQLException e) {
							handleSQLException(e);
						} finally {
							stmt.close();
						}
					}
					runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.POST_UPDATE, new AccountExtensibleObject(account, getServer()));
					removeRoles (sqlConnection, arg0);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.318"), e); //$NON-NLS-1$
		}
	}

	private void removeRoles(Connection sqlConnection, String accountName) throws SQLException, InternalErrorException {
		PreparedStatement stmt = sqlConnection
				.prepareStatement(sentence("SELECT GRANTED_ROLE FROM SYS.DBA_ROLE_PRIVS WHERE GRANTEE=?")); //$NON-NLS-1$
		stmt.setString(1, accountName.toUpperCase());
		ResultSet rset = stmt.executeQuery();
		Statement stmt2 = sqlConnection.createStatement();
		while (rset.next()) {
			String role = rset.getString(1);

			RoleGrant r = new RoleGrant();
			r.setRoleName(role);
			r.setSystem(getAgentName());
			r.setOwnerAccountName(accountName);
			r.setOwnerSystem(getSystem().getName());

			if ( runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
					runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
					runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
					runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
					runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer()))) 
			{
				stmt2.execute("REVOKE \"" + role + "\" FROM \"" + accountName.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				boolean ok = runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
						runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
						runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
						runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
						runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())); 
			} else {
				if (debug)
					log.info("Grant not revoked due to pre-delete trigger failure");
			}
		}
		rset.close();
		stmt.close();
	}

	public void updateUser(Account acc)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		if (debug) log.info("updateUser(String nom, String descripcio)");
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		
		String accountName = acc.getName();
		Collection<RoleGrant> roles;

		int i;

		// Control de acceso (tabla de roles)
		boolean cacActivo = false; // indica si está activo el control de acceso
		PreparedStatement stmtCAC = null;
		ResultSet rsetCAC = null;

		try {
			// Obtener los datos del usuario
			roles = getServer().getAccountRoles(accountName,
					this.getSystem().getName());

			Connection sqlConnection = getConnection();

			// Comprobamos que exista la tabla de roles de control de acceso
			stmtCAC = sqlConnection
					.prepareStatement(sentence("select 1 from user_tables where table_name ='SC_OR_ROLE'")); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (rsetCAC.next()) {
				cacActivo = true; // la tabla existe (no miramos si está activo
									// o no, nos da igual)
			}
			rsetCAC.close();
			stmtCAC.close();

			// Comprobar si el usuario existe
			stmt = sqlConnection
					.prepareStatement(sentence("SELECT 1 FROM SYS.DBA_USERS WHERE USERNAME=?")); //$NON-NLS-1$
			stmt.setString(1, accountName.toUpperCase());
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			final boolean newUser = !rset.next();
			if (newUser) {
				stmt.close();

				Password pass = getServer().getOrGenerateUserPassword(accountName,
						getSystem().getName());

				if (! runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.PRE_INSERT, new AccountExtensibleObject(acc, getServer()))) {
					if (debug)
						log.info("Ignoring creation of user "+acc.getName()+" due to pre-insert trigger failure");
					return ;
				}

				String cmd = "CREATE USER \"" + accountName.toUpperCase() + "\" IDENTIFIED BY \"" + //$NON-NLS-1$ //$NON-NLS-2$
						quotePassword(pass) + "\"";
				if (defaultProfile != null && !defaultProfile.trim().isEmpty())
					cmd += " PROFILE " + defaultProfile;
				if (temporaryTablespace != null && !temporaryTablespace.trim().isEmpty())
					cmd += " TEMPORARY TABLESPACE " + temporaryTablespace;
				if (defaultTablespace != null && !defaultTablespace.trim().isEmpty())
					cmd += " DEFAULT TABLESPACE " + defaultTablespace;
				cmd += " ACCOUNT UNLOCK PASSWORD EXPIRE";

				stmt = sqlConnection.prepareStatement(sentence(cmd));
				stmt.execute();
			} else {
				if (! runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.PRE_UPDATE, new AccountExtensibleObject(acc, getServer()))) {
					if (debug)
						log.info("Ignoring update of user "+acc.getName()+" due to pre-update trigger failure");
					return;
				}
				

			}

			rset.close();
			stmt.close();
			// Dar o revocar permiso de create session : La part de revocar
			// passada a removeUser()
			stmt = sqlConnection
					.prepareStatement(sentence("GRANT CREATE SESSION TO  \"" + accountName.toUpperCase() + "\"")); //$NON-NLS-1$ //$NON-NLS-2$
			stmt.execute();
			stmt.close();

			// Eliminar los roles que sobran
			stmt = sqlConnection
					.prepareStatement(sentence("SELECT GRANTED_ROLE FROM SYS.DBA_ROLE_PRIVS WHERE GRANTEE=?")); //$NON-NLS-1$
			stmt.setString(1, accountName.toUpperCase());
			rset = stmt.executeQuery();
			stmt2 = sqlConnection.prepareStatement("select 1 from dual"); //no s'admet constructor buit //$NON-NLS-1$
			while (rset.next()) {
				boolean found = false;
				String role = rset.getString(1);

				for (RoleGrant ro : roles) {
					if (ro != null && ro.getRoleName().equalsIgnoreCase(role)) {
						found = true;
						ro = null;
					}
				}
				if (!found) {
					RoleGrant r = new RoleGrant();
					r.setRoleName(role);
					r.setSystem(getAgentName());
					r.setOwnerAccountName(acc.getName());
					r.setOwnerSystem(acc.getSystem());

					if ( runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer()))) 
					{
						stmt2.execute("REVOKE \"" + role + "\" FROM \"" + user.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						boolean ok = runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())); 
					} else {
						if (debug)
							log.info("Grant not revoked due to pre-delete trigger failure");
					}
				}
			}
			rset.close();
			stmt.close();

			String rolesPorDefecto = null;

			// Crear los roles si son necesarios
			for (RoleGrant r : roles) {
				if (r != null) {
					if (rolesPorDefecto == null)
						rolesPorDefecto = "\"" + r.getRoleName().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
					else
						rolesPorDefecto = rolesPorDefecto
								+ ",\"" + r.getRoleName().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
					stmt = sqlConnection
							.prepareStatement(sentence("SELECT 1 FROM SYS.DBA_ROLES WHERE ROLE=?")); //$NON-NLS-1$
					stmt.setString(1, r.getRoleName().toUpperCase());
					rset = stmt.executeQuery();
					if (!rset.next()) {
						Role role = getServer().getRoleInfo(r.getRoleName(), getAgentName());
						if ( runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.PRE_INSERT, new com.soffid.iam.sync.engine.extobj.RoleExtensibleObject(role, getServer())) ) 
						{
							// Password protected or not
							String command = "CREATE ROLE \"" + r.getRoleName().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
							if (getServer().getRoleInfo(r.getRoleName(),
									r.getSystem()).getPassword())
								command = command
										+ " IDENTIFIED BY \"" + rolePassword.getPassword().replaceAll("\"", PASSWORD_QUOTE_REPLACEMENT) + "\""; //$NON-NLS-1$ //$NON-NLS-2$
							stmt2.execute(command);
							// Revoke de mi mismo
							stmt2.execute("REVOKE \"" + r.getRoleName().toUpperCase() + "\" FROM \"" + this.user.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
							runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.POST_INSERT, new com.soffid.iam.sync.engine.extobj.RoleExtensibleObject(role, getServer()));
						} else {
							if (debug)
								log.info("Grant not executed due to pre-insert trigger failure");
						}
					} else {
						String command = "ALTER ROLE \"" + r.getRoleName().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
						if (getServer().getRoleInfo(r.getRoleName(),
								r.getSystem()).getPassword())
							command = command
									+ " IDENTIFIED BY \"" + rolePassword.getPassword().replaceAll("\"", PASSWORD_QUOTE_REPLACEMENT) + "\""; //$NON-NLS-1$ //$NON-NLS-2$
						else
							command = command + " NOT IDENTIFIED"; //$NON-NLS-1$
						stmt2.execute(command);
					}
					rset.close();
					stmt.close();
				}
			}

			// Añadir los roles que no tiene
			for (RoleGrant r : roles) {
				if (r != null) {
					if ( runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer()))) 
					{
						stmt2.execute("GRANT \"" + r.getRoleName().toUpperCase() + "\" TO  \"" + accountName.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						boolean ok = runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())); 
					} else {
						if (debug)
							log.info("Grant not executed due to pre-insert trigger failure");
					}
				}
			}

			// Ajustar los roles por defecto
			if (rolesPorDefecto == null)
				rolesPorDefecto = "NONE"; //$NON-NLS-1$
			String ss = "ALTER USER \"" + accountName.toUpperCase() + "\" DEFAULT ROLE " + rolesPorDefecto; //$NON-NLS-1$ //$NON-NLS-2$
			stmt2.execute(ss);

			runTriggers(SoffidObjectType.OBJECT_ACCOUNT, newUser ? SoffidObjectTrigger.POST_INSERT : SoffidObjectTrigger.POST_UPDATE, new AccountExtensibleObject(acc, getServer()));

			// Insertamos en la tabla de roles para CONTROL DE ACCESO (¿solo si
			// el usuario está activo??)
			if (Boolean.TRUE.equals( getSystem().getAccessControl()))
			{
				String[] rolesCAC = concatRoleNames(roles);
				HashSet grupsAndRolesHash = (rolesCAC != null && rolesCAC.length != 0) ? new HashSet(
						Arrays.asList(rolesCAC)) // eliminem repetits
						: new HashSet(); // evitem error al ésser llista buida
				rolesCAC = (String[]) grupsAndRolesHash.toArray(new String[0]);
				// 1) Obtenemos los roles que ya tiene
				stmt = sqlConnection
						.prepareStatement(sentence("SELECT SOR_GRANTED_ROLE FROM SC_OR_ROLE WHERE SOR_GRANTEE=?")); //$NON-NLS-1$
				stmt.setString(1, accountName.toUpperCase());
				rset = stmt.executeQuery();
				stmt2 = sqlConnection.prepareStatement("select 1 from dual"); //$NON-NLS-1$
				while (rset.next()) {
					boolean found = false;
					String role = rset.getString(1);
					for (i = 0; rolesCAC != null && !found && i < rolesCAC.length; i++) {
						if (rolesCAC[i] != null
								&& rolesCAC[i].equalsIgnoreCase(role)) {
							found = true;
							rolesCAC[i] = null;
						}
					}
					if (!found) {
						stmt2.execute("DELETE FROM SC_OR_ROLE WHERE SOR_GRANTEE='" //$NON-NLS-1$
								+ accountName.toUpperCase() + "' AND SOR_GRANTED_ROLE ='" //$NON-NLS-1$
								+ role.toUpperCase() + "'"); //$NON-NLS-1$
						stmt2.close();
					}
				}
				rset.close();
				stmt.close();
				// Añadir los roles que no tiene
				if (rolesCAC != null)
					for (i = 0; i < rolesCAC.length; i++) {
						if (rolesCAC[i] != null) {
							stmt2 = sqlConnection
									.prepareStatement(sentence("INSERT INTO SC_OR_ROLE (SOR_GRANTEE, SOR_GRANTED_ROLE) SELECT '" //$NON-NLS-1$
											+ accountName.toUpperCase()
											+ "', '" + rolesCAC[i].toUpperCase() + "' FROM DUAL ")); //$NON-NLS-1$ //$NON-NLS-2$
							stmt2.execute();
							stmt2.close();
						}
					}
			}
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {
		LinkedList<String> accounts = new LinkedList<String>();
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		Collection<RoleGrant> roles;

		int i;

		// Control de acceso (tabla de roles)
		boolean cacActivo = false; // indica si está activo el control de acceso
		PreparedStatement stmtCAC = null;
		ResultSet rsetCAC = null;

		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement(sentence("SELECT USERNAME FROM SYS.DBA_USERS")); //$NON-NLS-1$
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			while (rset.next()) {
				accounts.add(rset.getString(1));
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
		return accounts;
	}

	public Account getAccountInfo(String userAccount) throws RemoteException,
			InternalErrorException {
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		// Control de acceso (tabla de roles)
		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement(sentence("SELECT ACCOUNT_STATUS FROM SYS.DBA_USERS WHERE USERNAME=?")); //$NON-NLS-1$
			stmt.setString(1, userAccount);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (rset.next()) {
				Account account = new Account ();
				account.setName(userAccount);
				account.setName(userAccount);
				account.setSystem(getAgentName());
				account.setDisabled( ! "OPEN".equals(rset.getString(1)));
				return account;
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
		return null;
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		LinkedList<String> roles = new LinkedList<String>();
		PreparedStatement stmt = null;
		ResultSet rset = null;

		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement(sentence("SELECT ROLE FROM SYS.DBA_ROLES")); //$NON-NLS-1$
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			while (rset.next()) {
				roles.add(rset.getString(1));
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}
		return roles;
	}

	public Role getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		// Control de acceso (tabla de roles)
		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement(sentence("SELECT ROLE FROM SYS.DBA_ROLES WHERE ROLE=?")); //$NON-NLS-1$
			stmt.setString(1, roleName);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (rset.next()) {
				Role r = new Role();
				r.setSystem(getAgentName());
				r.setName(rset.getString(1));
				r.setDescription(rset.getString(1));
				return r;
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
		return null;
	}

	public List<RoleGrant> getAccountGrants(String userAccount)
			throws RemoteException, InternalErrorException {
		LinkedList<RoleGrant> roles = new LinkedList<RoleGrant>();
		PreparedStatement stmt = null;
		ResultSet rset = null;

		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement(sentence("SELECT GRANTED_ROLE FROM SYS.DBA_ROLE_PRIVS WHERE GRANTEE=?")); //$NON-NLS-1$
			stmt.setString(1,  userAccount);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			while (rset.next()) {
				RoleGrant rg = new RoleGrant();
				rg.setSystem(getAgentName());
				rg.setRoleName(rset.getString(1));
				rg.setOwnerAccountName(userAccount);
				rg.setOwnerSystem(getAgentName());
				roles.add(rg);
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}
		return roles;
	}
	
	private boolean runTriggers(SoffidObjectType objectType, SoffidObjectTrigger triggerType, 
			ExtensibleObject src) throws InternalErrorException {
		List<ObjectMappingTrigger> triggers = getTriggers (objectType, triggerType);
		for (ObjectMappingTrigger trigger: triggers)
		{
	
			ExtensibleObject eo = new ExtensibleObject();
			eo.setAttribute("source", src);
			eo.setAttribute("newObject", new HashMap());
			eo.setAttribute("oldObject", new HashMap());
			if ( ! objectTranslator.evalExpression(eo, trigger.getScript()) )
			{
				log.info("Trigger "+trigger.getTrigger().toString()+" returned false");
				return false;
			}
		}
		return true;
	}

	private List<ObjectMappingTrigger> getTriggers(SoffidObjectType objectType, SoffidObjectTrigger type) {
		List<ObjectMappingTrigger> triggers = new LinkedList<ObjectMappingTrigger>();
		if (objectMappings != null) {
			for ( ExtensibleObjectMapping objectMapping: objectMappings)
			{
				if (objectMapping.getSoffidObject().toString().equals(objectType.toString()))
				{
					for ( ObjectMappingTrigger trigger: objectMapping.getTriggers())
					{
						if (trigger.getTrigger() == type)
							triggers.add(trigger);
					}
				}
			}
		}
		return triggers;
	}

	public Collection<Map<String, Object>> invoke(String verb, String command,
			Map<String, Object> params) throws RemoteException, InternalErrorException 
	{
		ExtensibleObject o = new ExtensibleObject();
		if (params != null)
		o.putAll(params);
		if (command == null)
			command = "";
		if (verb != null && !verb.trim().isEmpty())
			command = verb.trim() + " " +command;
		List<Map<String, Object>> result = new LinkedList<Map<String,Object>>();
		executeSentence(command, o, null, result );
		return result;
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException {
		this.objectMappings = objects;
		objectTranslator = new ObjectTranslator(getSystem(), getServer(), objectMappings);
		objectTranslator.setObjectFinder(finder);
	}

	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}

	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}

	ExtensibleObjectFinder finder = new ExtensibleObjectFinder() {
		
		public Collection<Map<String, Object>> invoke(String verb, String command, Map<String, Object> params)
				throws InternalErrorException {
			try {
				return OracleAgent.this.invoke(verb, command, params);
			} catch (RemoteException e) {
				throw new InternalErrorException("Error executing command "+verb+" "+command, e);
			}
		}
		
		public ExtensibleObject find(ExtensibleObject pattern) throws Exception {
			return null;
		}
	};
	
	private int executeSentence(String sentence, ExtensibleObject obj, String filter, List<Map<String, Object>> result) throws InternalErrorException {
		StringBuffer b = new StringBuffer ();
		List<Object> parameters = new LinkedList<Object>();
		if (result != null)
			result.clear();
		
		Object cursor = new Object();
		parseSentence(sentence, obj, b, parameters, cursor);
		
		String parsedSentence = b.toString().trim();
		
		if (debug)
		{
			log.info("Executing "+parsedSentence);
			for (Object param: parameters)
			{
				log.info("   Param: "+(param == null ? "null": param.toString()+" ["
						+param.getClass().toString()+"]"));
			}
		}
		
		Connection conn;
		try {
			conn = getConnection();
			conn.setAutoCommit(true);
		} catch (Exception e1) {
			throw new InternalErrorException("Error connecting to database ", e1);
		}
		if (parsedSentence.toLowerCase().startsWith("select"))
		{
			if (debug)
				log.info("Getting rows");
			QueryHelper qh = new QueryHelper(conn);
			qh.setEnableNullSqlObject(true);
			try {
				List<Object[]> rows = qh.select(parsedSentence, parameters.toArray());
				log.info("Got rows size = "+rows.size());
				int rowsNumber = 0;
				for (Object[] row: rows)
				{
					if (debug)
						log.info("Got row ");
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(obj.getObjectType());
					for (int i = 0; i < row.length; i ++)
					{
						String param = qh.getColumnNames().get(i);
						eo.setAttribute(param, row[i]);
					}
					rowsNumber ++;
					result.add(eo);
				}
				if (debug)
					log.info("Rows number = "+rowsNumber);
				return rowsNumber;
			} catch (SQLException e) {
				handleSQLException(e);
				throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
			}
		}
		else if (parsedSentence.toLowerCase().startsWith("update") || 
				parsedSentence.toLowerCase().startsWith("delete"))
		{
			QueryHelper qh = new QueryHelper(conn);
			qh.setEnableNullSqlObject(true);
			try {
				return qh.executeUpdate(parsedSentence, parameters.toArray());
			} catch (SQLException e) {
				handleSQLException(e);
				throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
			}
		} 
		else if (parsedSentence.toLowerCase().startsWith("{call") )
		{
			try {
				List<Object[]> r = executeCall(conn, null, parameters,
						cursor, parsedSentence);
				int rowsNumber = 0;
				Object [] header = null;
				for (Object[] row: r)
				{
					if (header == null)
						header = row;
					else
					{
						ExtensibleObject eo = new ExtensibleObject();
						eo.setObjectType(obj.getObjectType());
						for (int i = 0; i < row.length; i ++)
						{
							String param = header[i].toString();
							eo.setAttribute(param, row[i]);
						}
						rowsNumber ++;
						for (int i = 0; i < row.length; i ++)
						{
							String param = header[i].toString();
							if (obj.getAttribute(param) == null)
							{
								obj.setAttribute(param, row[i]);
							}
						}
						if (result != null)
							result.add(eo);
					}
				}
				return rowsNumber;
			} catch (SQLException e) {
				handleSQLException(e);
				throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
			}
		}
		else 
		{
			QueryHelper qh = new QueryHelper(conn);
			qh.setEnableNullSqlObject(true);
			try {
				qh.execute(parsedSentence, parameters.toArray());
				return 1;
			} catch (SQLException e) {
				handleSQLException(e);
				throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
			}
		}

	}

	private List<Object[]> executeCall(Connection conn, Long maxRows,
			List<Object> parameters, Object cursor, String parsedSentence)
			throws SQLException {
		List<Object[]> result = new LinkedList<Object[]>();
		LinkedList<String> columnNames = new LinkedList<String>();
		CallableStatement stmt = conn.prepareCall(parsedSentence);

		try {
			int num = 0;
			int cursorNumber = -1;
			for (Object param : parameters)
			{
				num++;
				if (param == null)
				{
					stmt.setNull(num, Types.VARCHAR);
				}
				else if (param == cursor)
				{
					stmt.registerOutParameter(num, OracleTypes.CURSOR);
					cursorNumber = num;
				}
				else if (param instanceof Long)
				{
					stmt.setLong(num, (Long) param);
				}
				else if (param instanceof Integer)
				{
					stmt.setInt(num, (Integer) param);
				}
				else if (param instanceof Date)
				{
					stmt.setDate(num, (java.sql.Date) param);
				}
				else if (param instanceof java.sql.Timestamp)
				{
					stmt.setTimestamp(num, (java.sql.Timestamp) param);
				}
				else
				{
					stmt.setString(num, param.toString());
				}
			}
			stmt.execute();
			if (cursorNumber >= 0)
			{
				long rows = 0;
				ResultSet rset = (ResultSet) stmt.getObject(cursorNumber);
				try
				{
					int cols = rset.getMetaData().getColumnCount();
					for (int i = 0; i < cols; i++)
					{
						columnNames.add (rset.getMetaData().getColumnLabel(i+1));
					}
					result.add(columnNames.toArray());
					while (rset.next() && (maxRows == null || rows < maxRows.longValue()))
					{
						rows++;
						Object[] row = new Object[cols];
						for (int i = 0; i < cols; i++)
						{
							Object obj = rset.getObject(i + 1);
							if (obj == null)
							{
								int type = rset.getMetaData().getColumnType(i+1);
								if (type == Types.BINARY ||
									type == Types.LONGVARBINARY ||
									type == Types.VARBINARY || type == Types.BLOB ||
									type == Types.DATE || type == Types.TIMESTAMP ||
									type == Types.TIME || type == Types.BLOB)
										row [i] = new NullSqlObjet(type);
							}
							else if (obj instanceof Date)
							{
								row[i] = rset.getTimestamp(i+1);
							}
							else if (obj instanceof BigDecimal)
							{
								row[i] = rset.getLong(i+1);
							}
							else
								row[i] = obj;
						}
						result.add(row);
					}
				}
				finally
				{
					rset.close();
				}
			}
		}
		finally
		{
			stmt.close();
		}
		return result;
	}

	
	private void parseSentence(String sentence, ExtensibleObject obj,
			StringBuffer parsedSentence, List<Object> parameters, Object outputCursor) {
		int position = 0;
		// First, transforma sentence into a valid SQL API sentence
		do
		{
			int nextQuote = sentence.indexOf('\'', position);
			int next = sentence.indexOf(':', position);
			if (next < 0)
			{
				parsedSentence.append (sentence.substring(position));
				position = sentence.length();
			}
			else if (nextQuote >= 0 && next > nextQuote)
			{
				parsedSentence.append (sentence.substring(position, nextQuote+1));
				position = nextQuote + 1;
			}
			else
			{
				parsedSentence.append (sentence.substring(position, next));
				int paramStart = next + 1;
				int paramEnd = paramStart;
				while (paramEnd < sentence.length() && 
						Character.isJavaIdentifierPart(sentence.charAt(paramEnd)))
				{
					paramEnd ++;
				}
				if (paramEnd == paramStart) // A := is being used
					parsedSentence.append (":");
				else
				{
					parsedSentence.append ("?");
					String param = sentence.substring(paramStart, paramEnd);
					Object paramValue =  obj.getAttribute(param);
					if (paramValue == null && param.toLowerCase().startsWith("return"))
						parameters.add(outputCursor);
					else
						parameters.add(paramValue);
				}
				position = paramEnd;
			}
		} while (position < sentence.length());
	}


}
