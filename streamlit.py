from pymongo import MongoClient
import pandas as pd
import streamlit as st
import plotly.express as px

class MongoDBHandler:
    def __init__(self, db_name='bisindo_color', collection_name='color', mongo_url='mongodb://localhost:27017/'):
        self.client = MongoClient(mongo_url)
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]

    def get_data_with_class_gender_and_date(self):
        # Retrieve all data from the MongoDB collection
        data = list(self.collection.find())

        # Create a DataFrame from the data
        df = pd.DataFrame(data)

        # Rename 'date' and 'time' to 'detection_date' if they exist
        if 'date' in df.columns and 'time' in df.columns:
            df['detection_date'] = pd.to_datetime(df['date'] + ' ' + df['time'])
            df = df.drop(columns=['date', 'time'])

        return df

# Initialize MongoDB handler
mongo_handler = MongoDBHandler()

# Streamlit sidebar for page selection
option = 'Dataframe'  # Default to 'Dataframe' page

if option == 'Dataframe':
    st.write("""## Dataframe""")  # Display the dataframe page title

    # Call the function to get data from MongoDB
    df = mongo_handler.get_data_with_class_gender_and_date()

    # Filter out the 'emas' color and include only the specified colors
    valid_colors = ['abu-abu', 'biru', 'coklat', 'hijau', 'hitam', 'kuning', 'merah', 'orange', 'pink', 'putih']
    df = df[df['class_name'].str.lower().isin(valid_colors)]

    # Dropdown for date range selection
    date_range = st.selectbox('Select date range:', ['1-10', '11-20', '21-30'])
    # Dropdown for gender selection
    gender_selection = st.selectbox('Select gender:', ['All', 'Male', 'Female'])

    # Filter the dataframe based on the selected date range
    if date_range == '1-10':
        df = df[(df['detection_date'].dt.day >= 1) & (df['detection_date'].dt.day <= 10)]
    elif date_range == '11-20':
        df = df[(df['detection_date'].dt.day >= 11) & (df['detection_date'].dt.day <= 20)]
    elif date_range == '21-30':
        df = df[(df['detection_date'].dt.day >= 21) & (df['detection_date'].dt.day <= 30)]

    # Filter the dataframe based on the selected gender
    if gender_selection != 'All':
        df = df[df['gender'].str.lower() == gender_selection.lower()]

    st.write("""## Draw Charts""")  # Display the charts title

    if 'class_name' in df.columns and 'gender' in df.columns:
        # Group data by class_name and gender
        grouped_data = df.groupby(['class_name', 'gender']).size().reset_index(name='Counts')

        # Create a bar chart
        fig = px.bar(grouped_data, x='class_name', y='Counts', color='gender', barmode='group',
                     title='Color Detection by Gender')

        # Display the bar chart
        st.plotly_chart(fig)
    else:
        st.warning("Required columns ('class_name' or 'gender') are not found in the data.")

    if 'detection_date' in df.columns:
        # Calculate and display the percentage of detections by day
        st.write("### Detection Percentage by Day:")
        day_counts = df['detection_date'].dt.day_name().value_counts()
        for day, count in day_counts.items():
            percentage = (count / len(df)) * 100
            st.write(f"- {day}: {percentage:.2f}%")

        # Create a bar chart for detections by day
        data_days = {'Day': day_counts.index, 'Counts': day_counts.values}
        fig_days = px.bar(data_days, x='Day', y='Counts', title='Detections by Day')

        # Display the bar chart for detections by day
        st.plotly_chart(fig_days)
    else:
        st.warning("The 'detection_date' column is not found in the data.")

    if 'gender' in df.columns:
        # Calculate and display the average detections by gender
        st.write("### Average Detections by Gender:")
        gender_counts = df['gender'].value_counts()
        for gender, count in gender_counts.items():
            average = (count / len(df)) * 100
            st.write(f"- {gender}: {average:.2f}%")

        # Create a bar chart for detections by gender
        data_gender = {'Gender': gender_counts.index, 'Counts': gender_counts.values}
        fig_gender = px.bar(data_gender, x='Gender', y='Counts', title='Average Detections by Gender')

        # Display the bar chart for detections by gender
        st.plotly_chart(fig_gender)
    else:
        st.warning("The 'gender' column is not found in the data.")
