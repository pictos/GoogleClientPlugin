using Windows.UI.Xaml.Navigation;

namespace TestAPp.UWP
{
    public sealed partial class MainPage
    {
        public MainPage()
        {
            this.InitializeComponent();

            LoadApplication(new TestAPp.App());
        }

        protected async override void OnNavigatedTo(NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);

            await Plugin.GoogleClient.CrossGoogleClient.Current.UserInfo(e);
        }
    }
}
