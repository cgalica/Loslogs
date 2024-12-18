import streamlit as st
import pandas as pd
import re
from io import StringIO
import matplotlib.pyplot as plt

# Configuración de matplotlib
plt.style.use('seaborn-v0_8-darkgrid')

# Título
st.title("Herramienta de análisis de logs")

# Configuración de navegación
menu = st.sidebar.radio("Selecciona una página", ["Análisis de Datos", "Gráficos"])

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
        log_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.+?)\] "(\w+) (.+?) HTTP/\d.\d" (\d{3}) (\d+)'
        uploaded_file.seek(0)
        log_lines = uploaded_file.getvalue().decode("utf-8").splitlines()
        parsed_lines = [
            re.match(log_pattern, line).groups()
            for line in log_lines if re.match(log_pattern, line)
        ]
        if parsed_lines:
            log_data = pd.DataFrame(parsed_lines, columns=["IP", "Fecha", "Método", "URL", "Código", "Bytes"])
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

    # Limpiar datos
    if log_data is not None:
        log_data = limpiar_dataframe(log_data)

    # Página de análisis de datos
    if menu == "Análisis de Datos":
        st.write("### Datos Cargados:")
        st.dataframe(log_data)

        # Filtros dinámicos
        with st.expander("Aplicar filtros", expanded=True):
            filters = {}

            for column in log_data.columns:
                column_type = log_data[column].dtype

                if pd.api.types.is_numeric_dtype(log_data[column]):
                    min_val, max_val = log_data[column].min(), log_data[column].max()
                    if min_val < max_val:  # Evita error en sliders iguales
                        rango = st.slider(
                            f"Rango de {column}",
                            min_value=float(min_val),
                            max_value=float(max_val),
                            value=(float(min_val), float(max_val))
                        )
                        filters[column] = (log_data[column] >= rango[0]) & (log_data[column] <= rango[1])

                elif pd.api.types.is_string_dtype(log_data[column]):
                    texto = st.text_input(f"Buscar en {column}:")
                    if texto:
                        filters[column] = log_data[column].str.contains(texto, case=False, na=False)

            for col, condition in filters.items():
                log_data = log_data[condition]

        st.write("### Datos Filtrados:")
        st.dataframe(log_data)

    # Página de gráficos
    elif menu == "Gráficos":
        if log_data is not None:
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
            if "Código" in log_data.columns:
                codigo_counts = log_data["Código"].value_counts()
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
    st.write("Sube un archivo de log para comenzar.")
