# Laboratorio Hands-On: Analisis de Trafico de Red

Wireshark + Nmap + decodificacion hexadecimal sobre una captura PCAP educativa.

Este repositorio documenta el analisis de `lab_traffic.pcap`, una captura simulada con escenarios clasicos de red: ARP, DNS, TCP, HTTP, ICMP, un SYN scan estilo Nmap y una sesion FTP insegura con credenciales visibles en texto claro.

## Entrega principal

El documento final es:

```text
Entrega_Final_Wireshark_Nmap.pdf
```

## Estructura del repositorio

```text
Parcial2/
|-- README.md
|-- .gitignore
|-- Entrega_Final_Wireshark_Nmap.docx
|-- Entrega_Final_Wireshark_Nmap.pdf
|-- lab_traffic.pcap
|-- lab_wireshark_nmap.pdf
`-- capturas_wireshark/
    |-- captura_01_apertura_pcap.png
    |-- captura_02_protocol_hierarchy.png
    |-- captura_03_ftp_user_pass.png
    |-- captura_04_ftp_tcp_stream.png
    |-- captura_05_tcp_handshake.png
    |-- captura_06_syn_scan.png
    |-- captura_07_puertos_abiertos.png
    |-- captura_08_puertos_cerrados.png
    |-- captura_09_http_tcp_stream.png
    `-- captura_10_hex_view_packet_8.png
```

## Mapa de evidencias

| Captura | Evidencia | Filtro o vista usada |
|---:|---|---|
| 1 | Apertura del archivo PCAP en Wireshark | Vista general |
| 2 | Jerarquia de protocolos | `Statistics > Protocol Hierarchy` |
| 3 | Usuario y password FTP en texto claro | `ftp || tcp.port==21` |
| 4 | Flujo TCP de la sesion FTP | `tcp.stream eq 9` |
| 5 | Three-way handshake TCP | `tcp.stream==0 && frame.number>=5 && frame.number<=7` |
| 6 | SYN scan hacia el objetivo | `ip.dst==10.0.0.99 && tcp.flags.syn==1` |
| 7 | Puertos abiertos por respuesta SYN-ACK | `tcp.flags==0x012 && ip.src==10.0.0.99` |
| 8 | Puertos cerrados por respuesta RST | `tcp.flags.reset==1 && ip.src==10.0.0.99` |
| 9 | Follow TCP Stream de HTTP | `tcp.stream eq 0` |
| 10 | Vista hexadecimal del paquete HTTP GET | Paquete 8 |

## Hallazgos principales

| Area | Resultado |
|---|---|
| IP cliente | `192.168.1.10` |
| IP objetivo | `10.0.0.99` |
| FTP usuario | `admin` |
| FTP password | `s3cr3tP@ssw0rd` |
| HTTP metodo | `GET` |
| HTTP URI | `/index.html` |
| HTTP respuesta | `200 OK` |
| HTTP servidor | `Apache/2.4.51` |
| HTTP Content-Type | `text/html; charset=UTF-8` |
| Puertos abiertos | `22`, `80`, `443`, `3306` |
| Puertos cerrados | `23`, `25`, `8080`, `4444` |

## Lectura rapida del ataque simulado

1. El cliente resuelve direcciones con ARP y consulta DNS para ubicar el objetivo.
2. Se observa un handshake TCP normal contra HTTP.
3. El trafico HTTP viaja sin cifrado, por lo que el request y la respuesta son legibles.
4. El cliente realiza descubrimiento con ICMP.
5. El SYN scan prueba varios puertos en `10.0.0.99`.
6. Las respuestas SYN-ACK indican puertos abiertos; las respuestas RST indican puertos cerrados.
7. La sesion FTP expone credenciales en texto claro, confirmando el riesgo de usar FTP en produccion.

## Como reproducir el analisis

Abrir el PCAP:

```powershell
wireshark lab_traffic.pcap
```

Ver resumen por terminal:

```powershell
tshark -r lab_traffic.pcap
```

Ver jerarquia de protocolos:

```powershell
tshark -r lab_traffic.pcap -q -z io,phs
```

Listar comandos FTP:

```powershell
tshark -r lab_traffic.pcap -o tcp.analyze_sequence_numbers:FALSE -Y "ftp || tcp.port==21" -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Info
```

Listar puertos sondeados:

```powershell
tshark -r lab_traffic.pcap -Y "ip.dst==10.0.0.99 && tcp.flags.syn==1" -T fields -e frame.number -e tcp.dstport -e _ws.col.Info
```


## Autor

Gabriel Paz - 221087
