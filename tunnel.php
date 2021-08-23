#!/bin/env php
<?php

define('LOG', true);
define('LOG_FILE_PATH', sys_get_temp_dir().'/tunnel.log');
define('CONFIG_FILE', __DIR__.'/config.json');
date_default_timezone_set('PRC');

class Tunnel
{
    private $m_sConfigFile;
    private $m_nConfigFileModifiedTime;
    private $m_nInterval = 30;
    private $m_arrConfig = [];
    private $m_bLogToFile;
    private $m_hLockFile;

    private $m_comShell;


    public function __construct($sConfigFile, $bLogToFile = true)
    {
        $this->m_sConfigFile = $sConfigFile;
        $this->m_bLogToFile  = $bLogToFile;

        $this->loadConfig();
        if ($this->win()) {
            if (class_exists('\COM')) {
                $this->m_comShell = new \COM('WScript.Shell');
            } else {
                throw new RuntimeException('Failed instantiate COM object. Make sure php_com_dotnet.dll extension is loaded.');
            }
        }
    }


    private function win()
    {
        return stripos(PHP_OS, 'WIN') === 0;
    }


    private function loadConfig()
    {
        if (!file_exists($this->m_sConfigFile)) {
            file_put_contents($this->m_sConfigFile, json_encode([
                "interval" => 30,
                "tunnels"  => [
                    [
                        "remote" => [
                            "host" => "",
                            "port" => "33028",
                            "ip"   => "0.0.0.0",
                        ],
                        "local"  => [
                            "port" => "80",
                            "ip"   => "127.0.0.1",
                        ]
                    ]
                ]
            ], JSON_PRETTY_PRINT));
            $this->log("Config file: {$this->m_sConfigFile} does not exists, template was generated. modify and run again.");
            exit(22);
        }

        if ($sContent = file_get_contents($this->m_sConfigFile)) {
            $this->m_arrConfig = json_decode($sContent, true);
            if (empty($this->m_arrConfig)) {
                throw new InvalidArgumentException("Could not parse json of file: {$this->m_sConfigFile}");
            }
            $this->m_nConfigFileModifiedTime = filemtime($this->m_sConfigFile);
            if (!empty($this->m_arrConfig['interval'])) {
                $this->m_nInterval = $this->m_arrConfig['interval'];
            }
        } else {
            throw new RuntimeException("Could not read the contents of file: {$this->m_sConfigFile}.");
        }
    }


    public function config()
    {
        $arrTunnels = empty($this->m_arrConfig['tunnels']) ? [] : $this->m_arrConfig['tunnels'];
        if (empty($arrTunnels)) {
            throw new InvalidArgumentException("No tunnel was configured.");
        }
        foreach ($arrTunnels as $arrTunnel) {
            $this->checkOrGenerateKey($arrTunnel);
        }
    }


    public function tunnel()
    {
        $this->m_hLockFile = fopen(sys_get_temp_dir().'/.tunnel.lock', 'w');
        if (empty($this->m_hLockFile)) {
            throw new RuntimeException("Could not open lock file: {$this->m_hLockFile}");
        }
        $bOk = flock($this->m_hLockFile, LOCK_EX | LOCK_NB);
        if (!$bOk) {
            exit("Single Instance Only".PHP_EOL);
        }

        $arrTunnels = empty($this->m_arrConfig['tunnels']) ? [] : $this->m_arrConfig['tunnels'];
        if (empty($arrTunnels)) {
            throw new InvalidArgumentException("No tunnel was configured.");
        }

        while (true) {
            foreach ($arrTunnels as $arrTunnel) {
                //var_dump($arrTunnel);
                if (!$this->checkSshTunnel($arrTunnel)) {
                    $this->makeSshTunnel($arrTunnel);
                }
            }

            sleep($this->m_nInterval);
            if ($this->m_nConfigFileModifiedTime && (filemtime($this->m_sConfigFile) > $this->m_nConfigFileModifiedTime)) {
                try {
                    $this->loadConfig();
                } catch (Exception $exception) {
                    $this->log("Load new config file failed: {$exception->getMessage()}");
                }
            }
        }

    }


    private function checkSshTunnel($arrTunnelConfig)
    {
        $sRemoteHost       = $this->getField($arrTunnelConfig, 'remote', 'host', null);
        $sRemoteListenIp   = $this->getField($arrTunnelConfig, 'remote', 'ip', '0.0.0.0');
        $sRemoteListenPort = $this->getField($arrTunnelConfig, 'remote', 'port', null);
        $sRemoteUser       = $this->getField($arrTunnelConfig, 'remote', 'user', 'tunnel');

        $sLocalIp   = $this->getField($arrTunnelConfig, 'local', 'ip', '0.0.0.0');
        $sLocalPort = $this->getField($arrTunnelConfig, 'local', 'port', false);

        $sId = "{$sRemoteListenIp}:{$sRemoteListenPort}:{$sLocalIp}:{$sLocalPort} {$sRemoteUser}@{$sRemoteHost}";
        if ($this->win()) {
            $comShell    = new \COM("winmgmts:\\\\.\\root\\CIMV2");
            $arrColItems = $comShell->ExecQuery("SELECT * FROM Win32_Process WHERE Name = 'ssh.exe'", null, 48);
            foreach ($arrColItems as $each) {
                $sCmd = $each->CommandLine;
                if (is_string($sCmd) && stripos($sCmd, $sId)) {
                    $this->log("Running: {$sId}");

                    return true;
                }
            }

            $this->log("Not running: {$sId}");

            return false;
        } else {
            $sCmd  = "ps -ef | grep '{$sId}' | grep -v grep";
            $sLast = exec($sCmd, $arrOutputs, $nExitCode);
            if ($nExitCode === 0) {
                $this->log("Running: {$sId}");

                return true;
            } elseif ($nExitCode === 1) {
                $this->log("Not running: {$sId}");
            } else {
                $this->log("Exec command: {$sCmd} failed: [{$nExitCode}]{$sLast}", "ERROR");
            }
        }

        return false;
    }


    private function makeSshTunnel($arrTunnelConfig)
    {
        $sRemoteHost       = $this->getField($arrTunnelConfig, 'remote', 'host', null);
        $sRemoteListenIp   = $this->getField($arrTunnelConfig, 'remote', 'ip', '0.0.0.0');
        $sRemoteListenPort = $this->getField($arrTunnelConfig, 'remote', 'port', null);
        $sRemoteUser       = $this->getField($arrTunnelConfig, 'remote', 'user', 'tunnel');

        $sLocalIp   = $this->getField($arrTunnelConfig, 'local', 'ip', '0.0.0.0');
        $sLocalPort = $this->getField($arrTunnelConfig, 'local', 'port', null);

        if ($this->win()) {
            $sOutRsa = __DIR__."/.tunnel-{$sRemoteHost}.key";
            if (strpos($sOutRsa, ' ')) {
                $this->log("Key path can not have space: {$sOutRsa}", 'ERROR');
                return;
            }
            $sOutRsa     = str_replace('\\', '/', $sOutRsa);
            $sCmdPostfix = " 2>&1";
            //https://superuser.com/questions/1296024/windows-ssh-permissions-for-private-key-are-too-open
            $sWinChmod = 'icacls "'.$sOutRsa.'" /inheritance:r && icacls "'.$sOutRsa.'" /grant:r "%username%":"(R)"';
            exec($sWinChmod, $arrOutputs);
            var_dump($arrOutputs);

            $sCmd = "ssh -vvvv -oPasswordAuthentication=no -oStrictHostKeyChecking=no -i {$sOutRsa} -CfNg -R {$sRemoteListenIp}:{$sRemoteListenPort}:{$sLocalIp}:{$sLocalPort} {$sRemoteUser}@{$sRemoteHost}";
            $sCmd = "cmd /C ({$sCmd}{$sCmdPostfix}) >NUL";
            $this->log("CMD: {$sCmd}", 'DEBUG');

            $comExec = $this->m_comShell->Exec($sCmd);
            if (!empty($comExec)) {
                $nPid = $comExec->ProcessID;
                $this->log("Ssh process started with PID: {$nPid}");
            } else {
                $this->log("Ssh process started failed");
            }
        } else {
            $sOutRsa     = "/root/.tunnel-{$sRemoteHost}.key";
            $sCmdPostfix = " >/dev/null 2>&1 &";
            chmod($sOutRsa, 0600);

            //-C  Requests gzip compression of all data
            //-T  Disable pseudo-tty allocation
            //-N  Do not execute a remote command. This is useful for just forwarding ports.
            //-f  Requests ssh to go to background just before command execution.
            //-n  Redirects stdin from /dev/null (actually, prevents reading from stdin).
            //-q  Quiet mode. Causes most warning and diagnostic messages to be suppressed.
            $sCmd = "ssh -vvvvv -oPasswordAuthentication=no -oServerAliveInterval=30 -oTCPKeepAlive=yes -oStrictHostKeyChecking=no -i '{$sOutRsa}' -CfNg -R {$sRemoteListenIp}:{$sRemoteListenPort}:{$sLocalIp}:{$sLocalPort} {$sRemoteUser}@{$sRemoteHost}";
            $sCmd = "{$sCmd}{$sCmdPostfix}";
            $this->log("CMD: {$sCmd}", 'DEBUG');
            $this->execSshCmd($sCmd);
        }
    }


    private function checkOrGenerateKey($arrTunnelConfig)
    {
        $sRemoteHost = $this->getField($arrTunnelConfig, 'remote', 'host', null);
        if (stripos(PHP_OS, 'WIN') === 0) {
            $sOutRsa = __DIR__."/.tunnel-{$sRemoteHost}.key";
        } else {
            $sOutRsa = "/root/.tunnel-{$sRemoteHost}.key";
        }

        $sRemoteListenPort = $this->getField($arrTunnelConfig, 'remote', 'port', null);
        $sLocalPort        = $this->getField($arrTunnelConfig, 'local', 'port', null);
        $sLocalHostName    = gethostname();
        $sKeyEmail         = "R{$sRemoteListenPort}_forward_to_L{$sLocalPort}@{$sLocalHostName}.tunnel";

        if (file_exists($sOutRsa)) {
            $this->manual($sOutRsa.'.pub', $sKeyEmail, $arrTunnelConfig);
            return;
        }

        $sCmd  = "ssh-keygen -q -t rsa -N '' -f {$sOutRsa} -C {$sKeyEmail}";
        $sLast = exec($sCmd, $arrOutput, $nExitCode);
        if ($nExitCode) {
            throw new RuntimeException("Could not generate ssh private key pair: [{$nExitCode}] {$sLast}");
        }

        chmod($sOutRsa, 0600);
        $this->log("SSH key pair: {$sOutRsa} generated success");
        $this->manual($sOutRsa.'.pub', $sKeyEmail, $arrTunnelConfig);
    }


    private function manual($sOutRsaPubFile, $sKeyEmail, $arrTunnelConfig)
    {
        $sRemoteHost = $this->getField($arrTunnelConfig, 'remote', 'host', null);
        $sRemoteUser = $this->getField($arrTunnelConfig, 'remote', 'user', 'tunnel');

        $sRsaPub = file_get_contents($sOutRsaPubFile);

        $sCmd = <<<CMD
adduser {$sRemoteUser} --shell=/bin/false
mkdir -p /home/{$sRemoteUser}/.ssh/
chmod 700 /home/{$sRemoteUser}/.ssh/
touch /home/{$sRemoteUser}/.ssh/authorized_keys && chmod 600 /home/{$sRemoteUser}/.ssh/authorized_keys
chown {$sRemoteUser}:{$sRemoteUser} -R /home/{$sRemoteUser}/.ssh/
if ! grep -q "{$sKeyEmail}" "/home/{$sRemoteUser}/.ssh/authorized_keys"; then
  echo "{$sRsaPub}" | tee -a /home/{$sRemoteUser}/.ssh/authorized_keys
fi
sed -i "s/#GatewayPorts no/GatewayPorts yes/" /etc/ssh/sshd_config
service sshd restart || systemctl restart sshd
echo "success"
exit 0

CMD;
        $this->log("Creating user: {$sRemoteUser} on host: {$sRemoteHost}", "NOTICE");
        $this->log("If to log in with a password, next enter the password of the root user", "NOTICE");


        if ($this->win()) {
            $sTmpSh = sys_get_temp_dir().'/.tunnel_tmp.sh';
            $sTmpSh = str_replace('\\', '/', $sTmpSh);
            file_put_contents($sTmpSh, $sCmd);
            $sSshCmd = "ssh -oStrictHostKeyChecking=no root@{$sRemoteHost} < {$sTmpSh}";
        } else {
            $sSshCmd = "ssh -oStrictHostKeyChecking=no root@{$sRemoteHost} '{$sCmd}'";
        }

        var_dump($sSshCmd);
        $this->execSshCmd($sSshCmd);
    }


    private function execSshCmd($sCmd)
    {
        $arrDescriptors = [
            0 => ["pipe", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"],
        ];

        $arrEnv = getenv();

        $arrPipes = [];
        $process  = proc_open($sCmd, $arrDescriptors, $arrPipes, __DIR__, $arrEnv);
        stream_set_blocking($arrPipes[1], true);
        stream_set_blocking($arrPipes[1], true);

        if (is_resource($process)) {
            $sStdout   = stream_get_contents($arrPipes[1]);//ask password is in tty, can not catch!
            $sStdError = stream_get_contents($arrPipes[2]);
            //var_dump($sStdout, $sStdError);
            echo "STDOUT: ".PHP_EOL."----------".PHP_EOL.$sStdout.PHP_EOL;
            echo "STDERR: ".PHP_EOL."----------".PHP_EOL.$sStdError.PHP_EOL;

            fclose($arrPipes[0]);
            fclose($arrPipes[1]);
            fclose($arrPipes[2]);
            $nExitCode = proc_close($process);

            $this->log("Ssh command exited with code: {$nExitCode}", 'DEBUG');
        }
    }


    public function kill()
    {
        if ($this->win()) {
            $comShell    = new \COM("winmgmts:\\\\.\\root\\CIMV2");
            $arrColItems = $comShell->ExecQuery("SELECT * FROM Win32_Process WHERE Name = 'ssh.exe'", null, 48);
            foreach ($arrColItems as $each) {
                $sCmd = $each->CommandLine;
                if (is_string($sCmd) && stripos($sCmd, 'oStrictHostKeyChecking')) {
                    //var_dump($sCmd);
                    $nHandle = $each->Handle;
                    if ($nHandle) {
                        exec('taskkill /F /PID '.$nHandle);
                        $this->log("Killed PID: {$nHandle}");
                    }

                    return true;
                }
            }
        } else {
            $sCmd      = "ps -ef | grep 'oStrictHostKeyChecking=no' | grep -v grep | awk '{ print \$2 }'";
            $nLastLine = exec($sCmd, $arrOutput, $nExitCode);
            var_dump($arrOutput);
            if ($nExitCode === 0) {
                if (count($arrOutput)) {
                    $sPids = implode(' ', $arrOutput);
                    $this->log("Killed PIDs: {$sPids}");
                    exec("kill {$sPids}");
                } else {
                    $this->log("No process to killing", "NOTICE");
                }

            } else {
                $this->log("Got error grep process", "NOTICE");
            }

        }
    }


    public function service()
    {

    }


    public function unservice()
    {

    }


    private function getField($arrEachTunnelConfig, $sMainField, $sSubField, $sDefault = null)
    {
        if (empty($arrEachTunnelConfig[$sMainField][$sSubField])) {
            if (is_null($sDefault)) {
                throw new InvalidArgumentException("Missing field: tunnels->{$sMainField}->{$sSubField} of tunnel in config file: ".$this->m_sConfigFile);
            }

            return $sDefault;
        }

        return $arrEachTunnelConfig[$sMainField][$sSubField];
    }


    public function log($sMessage, $sLevel = 'INFO')
    {
        $sNow = date('Y-m-d H:i:s');
        $sLog = "[{$sNow}] {$sLevel} - ".$sMessage.PHP_EOL;
        echo $sLog;
        if ($this->m_bLogToFile) {
            file_put_contents(LOG_FILE_PATH, $sLog, FILE_APPEND);
        }
    }


    public function __destruct()
    {
        if ($this->m_hLockFile) {
            flock($this->m_hLockFile, LOCK_UN);
            fclose($this->m_hLockFile);
            $this->m_hLockFile = null;
        }
    }

}

$tunnel = new Tunnel(CONFIG_FILE, LOG);
if ($argc > 1) {
    $sAction = $argv[1];
} else {
    $sAction = 'run';
}

try {
    switch ($sAction) {
        case 'config':
            $tunnel->config();
            break;
        case 'service':
            $tunnel->service();
            break;
        case 'unservice':
            $tunnel->unservice();
            break;
        case 'run':
            $tunnel->tunnel();
            break;
        case 'kill':
            $tunnel->kill();
            break;
        default:
            $sHelp = <<<HELP
Unknown command: {$sAction}
Usage:
    {$argv[0]}           Tunneling all
    {$argv[0]} config    Config and deployment remote
    {$argv[0]} run       Tunneling all
    {$argv[0]} kill      Killing all running ssh tunnel
    {$argv[0]} service   Register keepalive service to system(using crontab/schedule task)
    {$argv[0]} unservice Unregister keepalive service

HELP;
            echo $sHelp;
    }

} catch (Exception $exception) {
    $tunnel->log("Fatal Error: {$exception->getMessage()}", "FATAL");
}