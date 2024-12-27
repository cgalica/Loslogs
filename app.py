import streamlit as st
# Configurar el diseño de la página en ancho completo
st.set_page_config(layout="wide")
import pandas as pd
import re
from io import StringIO
import matplotlib.pyplot as plt
from st_aggrid import AgGrid
from st_aggrid.grid_options_builder import GridOptionsBuilder
from st_aggrid.shared import GridUpdateMode
import requests  # Para geolocalización
import pydeck as pdk

# Configuración de matplotlib
plt.style.use('seaborn-v0_8-darkgrid')

# Título
st.title("Herramienta de análisis de logs")

# Configuración de navegación
menu = st.sidebar.radio("Selecciona una página", ["Análisis de Datos", "Gráficos", "Geolocalización"])

# Subir archivo
uploaded_file = st.sidebar.file_uploader("Sube un archivo de log", type=["log", "txt", "csv"])

# Función para limpiar y normalizar el DataFrame
def limpiar_dataframe(df):
    for col in df.columns:
        if pd.api.types.is_datetime64_any_dtype(df[col]) or "date" in col.lower():
            df[col] = pd.to_datetime(df[col], errors="coerce")
        elif pd.api.types.is_numeric_dtype(df[col]):
            df[col] = df[col].fillna(0)
        else:
            df[col] = df[col].astype(str).replace("nan", "")
    return df

# Función para detectar columnas con IPs
def detectar_columnas_ip(df):
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    columnas_ip = []
    for column in df.columns:
        if df[column].dropna().apply(lambda x: bool(ip_pattern.match(str(x)))).any():
            columnas_ip.append(column)
    return columnas_ip

# Función para geolocalizar una IP usando ipinfo.io
def geolocalizar_ip(ip, token="AQUI VA LA KEY"):
    url = f"https://ipinfo.io/{ip}?token={token}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            loc = data.get("loc", "0,0").split(",")
            return {
                "IP": ip,
                "Ciudad": data.get("city", "Desconocido"),
                "Región": data.get("region", "Desconocido"),
                "País": data.get("country", "Desconocido"),
                "Latitud": float(loc[0]) if len(loc) == 2 else None,
                "Longitud": float(loc[1]) if len(loc) == 2 else None,
                "ISP": data.get("org", "Desconocido"),
            }
        else:
            return {"IP": ip, "Error": f"No se pudo obtener información: {response.status_code}"}
    except requests.RequestException as e:
        return {"IP": ip, "Error": str(e)}

# Define constant for "Código"
CODIGO_COLUMN = "Código"

# Procesamiento y análisis
if uploaded_file:
    log_type = st.sidebar.selectbox("Selecciona el tipo de log", ["IIS", "Apache", "Custom"])
    log_data = None

    # Procesar logs IIS
    if log_type == "IIS":
        filtered_lines = [
            line.decode("utf-8").strip()
            for line in uploaded_file
            if not line.decode("utf-8").startswith("#")
        ]
        log_data = pd.read_csv(
            StringIO("\n".join(filtered_lines)),
            sep=r'\s+',
            engine='python',
            on_bad_lines='skip'
        )

    # Procesar logs Apache
    elif log_type == "Apache":
        log_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.+?)\] \"(\w+) (.+?) HTTP/\d.\d\" (\d{3}) (\d+)'
        uploaded_file.seek(0)
        log_lines = uploaded_file.getvalue().decode("utf-8").splitlines()
        parsed_lines = [
            re.match(log_pattern, line).groups()
            for line in log_lines if re.match(log_pattern, line)
        ]
        if parsed_lines:
            log_data = pd.DataFrame(parsed_lines, columns=["IP", "Fecha", "Método", "URL", CODIGO_COLUMN, "Bytes"])
            log_data["Fecha"] = pd.to_datetime(log_data["Fecha"], format="%d/%b/%Y:%H:%M:%S %z", errors="coerce")

    # Procesar logs personalizados
    elif log_type == "Custom":
        uploaded_file.seek(0)
        filtered_lines = [
            line.decode("utf-8").strip()
            for line in uploaded_file
            if not line.decode("utf-8").startswith("#")
        ]
        log_data = pd.read_csv(
            StringIO("\n".join(filtered_lines)),
            sep=r'\s+',
            engine='python',
            on_bad_lines='skip'
        )

    # Limpiar datos y verificar si hay datos
    if log_data is not None:
        log_data = limpiar_dataframe(log_data)

        # Página de análisis de datos
        if menu == "Análisis de Datos":
            st.write("### Datos con Filtros Interactivos:")

            # Configurar opciones de AgGrid (Community Edition compatible)
            gb = GridOptionsBuilder.from_dataframe(log_data)
            gb.configure_pagination(paginationAutoPageSize=True)  # Activar paginación
            gb.configure_default_column(wrapHeaderText=True, autoHeight=True, editable=False, filter=True, sortable=True, resizable=True)

            grid_options = gb.build()

            # Mostrar la tabla con AgGrid
            AgGrid(
                log_data,
                gridOptions=grid_options,
                update_mode=GridUpdateMode.SELECTION_CHANGED,
                fit_columns_on_grid_load=True,
                theme="streamlit"  # Tema gratuito compatible
            )

        # Página de gráficos
        elif menu == "Gráficos":
            if log_data is not None and not log_data.empty:
                st.write("## Visualizaciones")

                # Distribución de IPs
                columnas_ip = detectar_columnas_ip(log_data)
                if columnas_ip:
                    for col in columnas_ip:
                        ip_counts = log_data[col].value_counts().head(10)
                        st.write(f"### Top 10 IPs en la columna {col}:")
                        fig, ax = plt.subplots()
                        ip_counts.plot(kind='bar', ax=ax)
                        ax.set_title(f"Distribución de IPs en {col}")
                        st.pyplot(fig)

                # Distribución de códigos HTTP
                if CODIGO_COLUMN in log_data.columns:
                    codigo_counts = log_data[CODIGO_COLUMN].value_counts()
                    st.write("### Distribución de Códigos HTTP")
                    fig, ax = plt.subplots()
                    codigo_counts.plot(kind='bar', ax=ax)
                    ax.set_title("Distribución de Códigos HTTP")
                    st.pyplot(fig)

                # Análisis temporal
                if "Fecha" in log_data.columns:
                    log_data["Fecha"] = pd.to_datetime(log_data["Fecha"], errors="coerce")
                    if log_data["Fecha"].notna().any():
                        log_data = log_data.set_index("Fecha")
                        st.write("### Análisis Temporal")
                        temporal_counts = log_data.resample("D").size()
                        fig, ax = plt.subplots()
                        temporal_counts.plot(kind='line', ax=ax)
                        ax.set_title("Eventos por Día")
                        st.pyplot(fig)
            else:
                st.write("No hay datos disponibles para generar gráficos.")

    # Nueva sección de geolocalización
    if menu == "Geolocalización":
        columnas_ip = detectar_columnas_ip(log_data)
        if columnas_ip:
            st.write("### Geolocalización de IPs")
            col_ip = st.selectbox("Selecciona la columna con IPs a geolocalizar", columnas_ip)
            if st.button("Geolocalizar IPs"):
                ip_data = log_data[col_ip].dropna().unique()[:20]  # Limitar a 20 IPs
                st.write("Procesando geolocalización, por favor espera...")
                geolocalizaciones = [geolocalizar_ip(ip) for ip in ip_data]
                geo_df = pd.DataFrame(geolocalizaciones)
                
                # Mostrar tabla con geolocalización
                st.write("### Resultados de Geolocalización:")
                st.dataframe(geo_df)

                # Crear mapa interactivo con pydeck
                st.write("### Mapa de Geolocalización:")
                geo_df = geo_df.dropna(subset=["Latitud", "Longitud"])
                geo_layer = pdk.Layer(
                    "ScatterplotLayer",
                    geo_df,
                    get_position="[Longitud, Latitud]",
                    get_radius=200000,
                    get_color="[0, 0, 255, 160]",
                    pickable=True
                )
                view_state = pdk.ViewState(
                    latitude=geo_df["Latitud"].mean(),
                    longitude=geo_df["Longitud"].mean(),
                    zoom=2,
                    pitch=0
                )
                r = pdk.Deck(layers=[geo_layer], initial_view_state=view_state, tooltip={"text": "{IP}\n{Ciudad}\n{ISP}"})
                st.pydeck_chart(r)

                # Descargar resultados como CSV
                st.download_button(
                    label="Descargar geolocalización como CSV",
                    data=geo_df.to_csv(index=False).encode("utf-8"),
                    file_name="geolocalizacion_ips.csv",
                    mime="text/csv"
                )
        else:
            st.write("No se encontraron columnas con IPs.")
else:
    st.write("Sube un archivo de log para comenzar.")